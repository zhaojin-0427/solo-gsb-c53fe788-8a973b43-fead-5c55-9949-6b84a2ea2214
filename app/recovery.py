"""Core damaged-ZIP recovery logic.

The parser walks the archive sequentially from offset 0 and validates every
local file header against its CRC-32 and size fields:

* STORED and DEFLATE entries are supported.
* Entries written with "streaming" flag (bit 3) carry their CRC-32 and sizes
  in a data descriptor *after* the data.  Both the signed (``PK\\x07\\x08``)
  and the unsigned 12-byte descriptor forms are recognised.
* DEFLATE streams are terminated by the deflate stream boundary itself
  (zlib ``unused_data``), the descriptor is then verified against the
  computed CRC-32 and lengths.
* STORED streams with unknown length are terminated by scanning for a
  descriptor whose CRC-32/length fields match the data that precedes it.

Only entries that form an unbroken, fully verifiable chain from offset 0 are
reported as ``certain``; anything recovered after a damaged segment is a
``candidate``.  A ``PK\\x03\\x04`` signature found inside garbage is never
trusted on its own - a candidate header must validate end-to-end (CRC-32 and
lengths) before it is accepted.  When more than one split validates, the
ambiguity is reported.
"""
from __future__ import annotations

import hashlib
import os
import struct
import zlib
from dataclasses import dataclass, field

LOCAL_SIG = b"PK\x03\x04"
CD_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
DD_SIG = b"PK\x07\x08"
EOCD64_LOC_SIG = b"PK\x06\x07"

LOCAL_HDR = struct.Struct("<I5H3I2H")   # 30 bytes
CD_HDR = struct.Struct("<I6H3I5H2I")    # 46 bytes
EOCD = struct.Struct("<I4H2IH")         # 22 bytes
DD = struct.Struct("<III")              # 12 bytes (without signature)

ENCRYPT_MASK = 0x0041          # bit 0: encrypted, bit 6: strong encryption
MASKED_LOCAL_HEADER = 0x2000   # bit 13: central-directory encryption marker
DATA_DESCRIPTOR_FLAG = 0x0008  # bit 3
UTF8_FLAG = 0x0800             # bit 11

KNOWN_METHODS = frozenset({0, 1, 6, 8, 9, 12, 14, 18, 19, 63, 95, 96, 97, 98, 99})

IN_CHUNK = 1 << 22   # 4 MiB slices fed to zlib / hashed at a time
OUT_MAX = 1 << 22    # 4 MiB cap per decompress() call -> bounded memory

MAX_DD_SIG_CANDIDATES = 64   # signed descriptors tested per STORED stream
MAX_STRUCT_CANDIDATES = 4    # next-structure guesses per signature type
MAX_RESUME_VALIDATIONS = 512  # candidate headers validated per archive


class Reject(Exception):
    """The whole upload must be rejected; no partial results may be kept."""

    status = 422

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class RejectLimit(Reject):
    """A size limit was exceeded (HTTP 413)."""

    status = 413


class EntryInvalid(Exception):
    """A candidate local header does not describe a valid entry."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Ctx:
    mm: object            # mmap, used for .find()
    data: object          # memoryview over the archive (zero-copy slicing)
    n: int                # archive size in bytes
    entry_dir: str        # where recovered payloads are written
    max_expanded: int
    total_expanded: int = 0
    scan_budget: int = 0
    validations: int = 0
    ambiguities: list = field(default_factory=list)

    def add_expanded(self, k: int) -> None:
        self.total_expanded += k
        if self.total_expanded > self.max_expanded:
            raise RejectLimit(
                f"cumulative decompressed size exceeds the limit of "
                f"{self.max_expanded} bytes"
            )

    def use_scan_budget(self, k: int) -> None:
        # Bounds the total amount of CRC scanning done for STORED entries
        # with unknown length (roughly 3 full passes over the archive).
        self.scan_budget += k
        if self.scan_budget > 3 * self.n + (1 << 20):
            raise EntryInvalid("descriptor scan budget exhausted")


@dataclass
class Entry:
    index: int
    name: str
    offset: int
    header_size: int
    data_offset: int
    end_offset: int
    method: int
    flags: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    sha256: str = ""
    descriptor: str | None = None
    status: str = "candidate"


def decode_name(raw: bytes, flags: int) -> str:
    enc = "utf-8" if flags & UTF8_FLAG else "cp437"
    return raw.decode(enc, errors="replace")


def _check_zip64_extra(extra) -> None:
    i = 0
    n = len(extra)
    while i + 4 <= n:
        hid, hlen = struct.unpack_from("<HH", extra, i)
        if hid == 0x0001:
            raise Reject("ZIP64 archives are not supported")
        i += 4 + hlen


def _drain(ctx: Ctx, d: zlib.Decompress, inp, f, crc, sha, out_len):
    """Feed *inp* (plus any unconsumed tail) fully, bounding output chunks."""
    while True:
        try:
            out = d.decompress(inp, OUT_MAX)
        except zlib.error as e:
            raise EntryInvalid(f"invalid deflate stream: {e}") from None
        if out:
            crc = zlib.crc32(out, crc)
            sha.update(out)
            out_len += len(out)
            ctx.add_expanded(len(out))
            if f is not None:
                f.write(out)
        if d.unconsumed_tail:
            inp = d.unconsumed_tail
        elif not d.eof and out and len(out) == OUT_MAX:
            inp = b""  # flush output possibly pending without new input
        else:
            return crc, sha, out_len


def _copy_stored(ctx: Ctx, start: int, length: int, out_path):
    crc = 0
    sha = hashlib.sha256()
    f = open(out_path, "wb") if out_path else None
    try:
        pos, end = start, start + length
        while pos < end:
            chunk = ctx.data[pos:min(pos + IN_CHUNK, end)]
            crc = zlib.crc32(chunk, crc)
            sha.update(chunk)
            if f is not None:
                f.write(chunk)
            pos += len(chunk)
    finally:
        if f is not None:
            f.close()
    return crc, sha.hexdigest()


def _inflate_fixed(ctx: Ctx, start: int, csize: int, out_path):
    """Inflate exactly *csize* bytes; the stream must end there exactly."""
    d = zlib.decompressobj(-15)
    crc, sha, out_len = 0, hashlib.sha256(), 0
    f = open(out_path, "wb") if out_path else None
    try:
        pos, end = start, start + csize
        while pos < end and not d.eof:
            chunk = ctx.data[pos:min(pos + IN_CHUNK, end)]
            pos += len(chunk)
            crc, sha, out_len = _drain(ctx, d, chunk, f, crc, sha, out_len)
        if not d.eof:
            raise EntryInvalid("deflate stream truncated")
        if d.unused_data:
            raise EntryInvalid("deflate stream ends before declared size")
    finally:
        if f is not None:
            f.close()
    return crc, sha.hexdigest(), out_len


def _read_descriptor(ctx: Ctx, p: int, crc: int, comp_len: int, out_len: int,
                     amb: list):
    """Validate the data descriptor at *p* against computed values.

    Returns (end_offset, kind).  Both the signed 16-byte and the unsigned
    12-byte form are tried; if both validate the ambiguity is reported.
    """
    data, n = ctx.data, ctx.n
    opts = []
    if p + 16 <= n and bytes(data[p:p + 4]) == DD_SIG:
        c, cs, us = DD.unpack_from(data, p + 4)
        if c == crc and cs == comp_len and us == out_len:
            opts.append((p + 16, "signature"))
    if p + 12 <= n:
        c, cs, us = DD.unpack_from(data, p)
        if c == crc and cs == comp_len and us == out_len:
            opts.append((p + 12, "plain"))
    if not opts:
        raise EntryInvalid("data descriptor mismatch")
    # Prefer the explicit signed form when both interpretations validate.
    opts.sort(key=lambda o: 0 if o[1] == "signature" else 1)
    if len(opts) > 1:
        amb.append({
            "offset": p,
            "kind": "data_descriptor",
            "detail": "both signed and unsigned data descriptor "
                      "interpretations validate",
            "chosen": opts[0][0],
            "alternatives": [o[0] for o in opts[1:]],
        })
    return opts[0]


def _parse_deflate_stream(ctx: Ctx, start: int, out_path, amb: list):
    """Parse a DEFLATE stream of unknown length (data descriptor follows)."""
    d = zlib.decompressobj(-15)
    crc, sha, out_len, fed = 0, hashlib.sha256(), 0, 0
    f = open(out_path, "wb") if out_path else None
    try:
        pos = start
        while not d.eof:
            if pos >= ctx.n:
                raise EntryInvalid("deflate stream truncated")
            chunk = ctx.data[pos:pos + IN_CHUNK]
            pos += len(chunk)
            fed += len(chunk)
            crc, sha, out_len = _drain(ctx, d, chunk, f, crc, sha, out_len)
        comp_len = fed - len(d.unused_data)
    finally:
        if f is not None:
            f.close()
    end = start + comp_len
    end, kind = _read_descriptor(ctx, end, crc, comp_len, out_len, amb)
    return end, comp_len, out_len, crc, sha.hexdigest(), kind


def _parse_stored_stream(ctx: Ctx, start: int, out_path, amb: list):
    """Parse a STORED stream of unknown length by locating its descriptor.

    Candidate descriptor positions are signature hits plus the bytes just
    before any following ZIP structure; a single incremental CRC-32 pass
    validates them.  Every position whose (crc, csize, usize) triple matches
    the preceding data is a verifiable split point.
    """
    n = ctx.n
    cands = []
    p, found = start, 0
    while found < MAX_DD_SIG_CANDIDATES:
        p = ctx.mm.find(DD_SIG, p)
        if p < 0:
            break
        cands.append((p, "signature"))
        p += 4
        found += 1
    for sig in (LOCAL_SIG, CD_SIG, EOCD_SIG):
        q = start
        for _ in range(MAX_STRUCT_CANDIDATES):
            q = ctx.mm.find(sig, q)
            if q < 0:
                break
            if q - 12 >= start:
                cands.append((q - 12, "plain"))
            q += 4
    if n - 12 >= start:
        cands.append((n - 12, "plain"))

    valid = []  # (end_offset, kind, descriptor_offset, crc_at_descriptor)
    crc, cur = 0, start
    for p, kind in sorted(set(cands)):
        need = 16 if kind == "signature" else 12
        if p < start or p + need > n:
            continue
        ctx.use_scan_budget(p - cur)
        crc = zlib.crc32(ctx.data[cur:p], crc)
        cur = p
        length = p - start
        off = p + 4 if kind == "signature" else p
        c, cs, us = DD.unpack_from(ctx.data, off)
        if c == crc and cs == length and us == length:
            valid.append((p + need, kind, p, c))
    if not valid:
        raise EntryInvalid("stored data descriptor not found")

    chosen = valid[0]
    if len(valid) > 1:
        amb.append({
            "offset": chosen[2],
            "kind": "stored_descriptor",
            "detail": "multiple descriptor positions validate against the "
                      "preceding data",
            "chosen": chosen[0],
            "alternatives": [v[0] for v in valid[1:]],
        })
    end, kind, dd_start, crc_val = chosen
    out_len = dd_start - start
    ctx.add_expanded(out_len)

    sha = hashlib.sha256()
    f = open(out_path, "wb") if out_path else None
    try:
        pos = start
        while pos < dd_start:
            chunk = ctx.data[pos:min(pos + IN_CHUNK, dd_start)]
            sha.update(chunk)
            if f is not None:
                f.write(chunk)
            pos += len(chunk)
    finally:
        if f is not None:
            f.close()
    return end, out_len, out_len, crc_val, sha.hexdigest(), kind


def _plausible_header(ctx: Ctx, pos: int, nlen: int, elen: int, method: int,
                      ver: int) -> bool:
    """Heuristic: is this a believable header (not random garbage)?

    Used only to decide whether an encryption flag found while scanning a
    damaged region should reject the whole upload.
    """
    if not (1 <= nlen <= 1024) or elen > 4096 or ver > 100:
        return False
    if method not in KNOWN_METHODS:
        return False
    name = bytes(ctx.data[pos + 30:pos + 30 + nlen])
    if b"\x00" in name:
        return False
    return all(0x20 <= b < 0x7F or b >= 0x80 for b in name)


def parse_entry_at(ctx: Ctx, pos: int, store: bool, idx: int, amb: list,
                   strict: bool) -> Entry:
    """Parse and fully validate one local file entry at *pos*.

    Raises EntryInvalid if the entry does not validate, Reject if the whole
    upload must be refused (encryption / ZIP64 / expansion limit).
    """
    data, n = ctx.data, ctx.n
    if pos + 30 > n:
        raise EntryInvalid("truncated local file header")
    (sig, ver, flags, method, _mt, _md, crc, csize, usize,
     nlen, elen) = LOCAL_HDR.unpack_from(data, pos)
    if sig != 0x04034B50:
        raise EntryInvalid("bad local file header signature")
    if pos + 30 + nlen + elen > n:
        raise EntryInvalid("truncated local file header")
    if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF:
        raise Reject("ZIP64 archives are not supported")
    _check_zip64_extra(data[pos + 30 + nlen:pos + 30 + nlen + elen])

    if flags & (ENCRYPT_MASK | MASKED_LOCAL_HEADER):
        # In the contiguous chain this is certainly a real header.  Inside a
        # damaged region random bytes may carry the flag, so only plausible
        # headers reject the upload outright.
        if strict or _plausible_header(ctx, pos, nlen, elen, method, ver):
            raise Reject("encrypted entries are not supported")
        raise EntryInvalid("encrypted entry")

    if method not in (0, 8):
        raise EntryInvalid(f"unsupported compression method {method}")

    name = decode_name(bytes(data[pos + 30:pos + 30 + nlen]), flags)
    data_start = pos + 30 + nlen + elen
    ent = Entry(index=idx, name=name, offset=pos, header_size=30 + nlen + elen,
                data_offset=data_start, end_offset=0, method=method,
                flags=flags, crc32=crc, compressed_size=0, uncompressed_size=0)
    out_path = os.path.join(ctx.entry_dir, f"{idx}.bin") if store else None

    try:
        if flags & DATA_DESCRIPTOR_FLAG:
            if method == 8:
                end, comp_len, out_len, crc_val, sha, kind = \
                    _parse_deflate_stream(ctx, data_start, out_path, amb)
            else:
                end, comp_len, out_len, crc_val, sha, kind = \
                    _parse_stored_stream(ctx, data_start, out_path, amb)
            ent.descriptor = kind
            ent.crc32 = crc_val
            ent.compressed_size = comp_len
            ent.uncompressed_size = out_len
            ent.sha256 = sha
            ent.end_offset = end
        else:
            if data_start + csize > n:
                raise EntryInvalid("entry data truncated")
            if method == 0:
                if csize != usize:
                    raise EntryInvalid("stored entry size mismatch")
                ctx.add_expanded(usize)
                crc_val, sha = _copy_stored(ctx, data_start, csize, out_path)
                out_len = usize
            else:
                crc_val, sha, out_len = _inflate_fixed(ctx, data_start, csize,
                                                       out_path)
                if out_len != usize:
                    raise EntryInvalid("deflate entry size mismatch")
            if crc_val != crc:
                raise EntryInvalid("crc32 mismatch")
            ent.compressed_size = csize
            ent.uncompressed_size = out_len
            ent.sha256 = sha
            ent.end_offset = data_start + csize
    except EntryInvalid:
        if out_path:
            try:
                os.unlink(out_path)
            except OSError:
                pass
        raise
    return ent


def find_next_valid(ctx: Ctx, start: int, amb: list):
    """Scan a damaged region for the next verifiable local file header.

    A signature alone is never enough: every candidate must validate
    end-to-end.  Returns the chosen offset or None.  If several positions
    validate, the ambiguity is reported and the first one is used.
    """
    p = start
    valid = []
    while ctx.validations < MAX_RESUME_VALIDATIONS:
        p = ctx.mm.find(LOCAL_SIG, p)
        if p < 0:
            break
        ctx.validations += 1
        saved = ctx.total_expanded
        try:
            parse_entry_at(ctx, p, store=False, idx=-1, amb=[], strict=False)
            valid.append(p)
        except RejectLimit:
            pass  # a fake header acting as a zip bomb is simply invalid
        except EntryInvalid:
            pass
        finally:
            ctx.total_expanded = saved  # dry runs do not consume budget
        if len(valid) >= 4:
            break
        p += 4
    if not valid:
        return None
    if len(valid) > 1:
        amb.append({
            "offset": valid[0],
            "kind": "resume_point",
            "detail": "multiple verifiable entry positions exist after the "
                      "damaged region; the first was chosen",
            "chosen": valid[0],
            "alternatives": valid[1:],
        })
    return valid[0]


def _find_eocd(mm, n: int):
    """Locate and validate the End Of Central Directory record (if any)."""
    if n < 22:
        return None
    start = max(0, n - (22 + 65535))
    tail = bytes(mm[start:])
    i = tail.rfind(EOCD_SIG)
    while i >= 0:
        abs_i = start + i
        if i + 22 <= len(tail):
            (sig, dsk, cddsk, de, te, cdsz, cdoff, coml) = \
                EOCD.unpack_from(tail, i)
            if i + 22 + coml == len(tail):
                if (dsk == 0xFFFF or cddsk == 0xFFFF or de == 0xFFFF
                        or te == 0xFFFF or cdsz == 0xFFFFFFFF
                        or cdoff == 0xFFFFFFFF):
                    raise Reject("ZIP64 archives are not supported")
                if abs_i >= 20 and bytes(mm[abs_i - 20:abs_i - 16]) == \
                        EOCD64_LOC_SIG:
                    raise Reject("ZIP64 archives are not supported")
                return {"offset": abs_i, "entries": te, "cd_offset": cdoff,
                        "cd_size": cdsz, "end": abs_i + 22 + coml}
        i = tail.rfind(EOCD_SIG, 0, i)
    # No EOCD: a plausible ZIP64 locator near the end still means ZIP64.
    j = tail.rfind(EOCD64_LOC_SIG)
    if j >= 0 and j + 20 <= len(tail):
        _sig, disk, off64, disks = struct.unpack_from("<IIQI", tail, j)
        if disks <= 4096 and off64 < n:
            raise Reject("ZIP64 archives are not supported")
    return None


def _parse_eocd_at(view, p: int, n: int):
    if p + 22 > n:
        return None
    (sig, dsk, cddsk, de, te, cdsz, cdoff, coml) = EOCD.unpack_from(view, p)
    if (dsk == 0xFFFF or cddsk == 0xFFFF or de == 0xFFFF or te == 0xFFFF
            or cdsz == 0xFFFFFFFF or cdoff == 0xFFFFFFFF):
        raise Reject("ZIP64 archives are not supported")
    end = p + 22 + coml
    if end > n:
        return None
    return {"offset": p, "entries": te, "cd_offset": cdoff, "cd_size": cdsz,
            "end": end}


def _parse_cd(ctx: Ctx, pos: int):
    """Parse central directory headers starting at *pos*.

    Returns (cd_entries, failure_offset, eocd_or_None).  May raise Reject.
    """
    view, n = ctx.data, ctx.n
    cd = []
    p = pos
    while p + 4 <= n and bytes(view[p:p + 4]) == CD_SIG:
        if p + 46 > n:
            return cd, p, None
        (sig, _vm, _vn, flags, method, _mt, _md, crc, cs, us,
         nl, el, cl, disk, _ia, _xa, lho) = CD_HDR.unpack_from(view, p)
        if flags & (ENCRYPT_MASK | MASKED_LOCAL_HEADER):
            raise Reject("encrypted entries are not supported")
        if (cs == 0xFFFFFFFF or us == 0xFFFFFFFF or lho == 0xFFFFFFFF
                or disk == 0xFFFF):
            raise Reject("ZIP64 archives are not supported")
        if p + 46 + nl + el + cl > n:
            return cd, p, None
        _check_zip64_extra(view[p + 46 + nl:p + 46 + nl + el])
        name = decode_name(bytes(view[p + 46:p + 46 + nl]), flags)
        cd.append({"offset": lho, "name": name, "crc32": crc,
                   "compressed_size": cs, "uncompressed_size": us,
                   "method": method})
        p += 46 + nl + el + cl
    if p + 4 <= n and bytes(view[p:p + 4]) == EOCD_SIG:
        eocd = _parse_eocd_at(view, p, n)
        if eocd is None:
            return cd, p, None
        return cd, p, eocd
    return cd, p, None


def _check_consistency(cd: list, entries: list, eocd: dict,
                       cd_start: int) -> bool:
    if eocd["cd_offset"] != cd_start or eocd["entries"] != len(cd):
        return False
    if eocd["cd_size"] != eocd["offset"] - cd_start:
        return False
    if len(cd) != len(entries):
        return False
    for c, e in zip(cd, entries):
        if c["offset"] != e.offset or c["name"] != e.name:
            return False
        if (c["crc32"] != e.crc32
                or c["compressed_size"] != e.compressed_size
                or c["uncompressed_size"] != e.uncompressed_size):
            return False
    return True


def recover_archive(mm, view, n: int, entry_dir: str,
                    max_expanded: int) -> dict:
    """Recover as many entries as possible from the archive in *mm*."""
    ctx = Ctx(mm=mm, data=view, n=n, entry_dir=entry_dir,
              max_expanded=max_expanded)
    entries: list[Entry] = []
    damaged: list[dict] = []
    amb: list[dict] = ctx.ambiguities

    eocd_info = _find_eocd(mm, n)  # raises Reject on ZIP64
    cd_report = {"found": False, "offset": None, "entries": None,
                 "consistent": False, "notes": []}

    pos = 0
    chain = True  # unbroken verifiable chain from offset 0
    while pos < n:
        sig4 = bytes(view[pos:pos + 4])
        if sig4 == LOCAL_SIG:
            try:
                ent = parse_entry_at(ctx, pos, store=True, idx=len(entries),
                                     amb=amb, strict=True)
            except EntryInvalid as ex:
                chain = False
                nxt = find_next_valid(ctx, pos + 1, amb)
                if nxt is None:
                    damaged.append({"offset": pos, "length": n - pos,
                                    "reason": ex.reason})
                    pos = n
                else:
                    damaged.append({"offset": pos, "length": nxt - pos,
                                    "reason": ex.reason})
                    pos = nxt
                continue
            ent.status = "certain" if chain else "candidate"
            entries.append(ent)
            pos = ent.end_offset
        elif sig4 in (CD_SIG, EOCD_SIG):
            break
        else:
            chain = False
            nxt = find_next_valid(ctx, pos + 1, amb)
            if nxt is None:
                damaged.append({"offset": pos, "length": n - pos,
                                "reason": "unrecognized data"})
                pos = n
            else:
                damaged.append({"offset": pos, "length": nxt - pos,
                                "reason": "unrecognized data"})
                pos = nxt

    # Central directory / end record, if the scan reached it.
    if pos < n and bytes(view[pos:pos + 4]) == CD_SIG:
        cd_entries, fail_off, eocd = _parse_cd(ctx, pos)
        if eocd is None:
            damaged.append({"offset": fail_off, "length": n - fail_off,
                            "reason": "central directory truncated or end "
                                      "record missing"})
            cd_report["notes"].append("central directory is damaged")
        else:
            cd_report.update(found=True, offset=pos,
                             entries=eocd["entries"])
            if _check_consistency(cd_entries, entries, eocd, pos):
                cd_report["consistent"] = True
            else:
                cd_report["notes"].append(
                    "central directory does not match local header recovery")
            if eocd["end"] < n:
                damaged.append({"offset": eocd["end"],
                                "length": n - eocd["end"],
                                "reason": "trailing data after end of "
                                          "central directory"})
        pos = n
    elif pos < n and bytes(view[pos:pos + 4]) == EOCD_SIG:
        eocd = _parse_eocd_at(view, pos, n)
        if eocd is None:
            damaged.append({"offset": pos, "length": n - pos,
                            "reason": "malformed end of central directory"})
        else:
            cd_report.update(found=True, offset=eocd["cd_offset"],
                             entries=eocd["entries"])
            if eocd["entries"] == len(entries) and eocd["cd_offset"] == pos:
                cd_report["consistent"] = True
            else:
                cd_report["notes"].append(
                    "end of central directory does not match local header "
                    "recovery")
            if eocd["end"] < n:
                damaged.append({"offset": eocd["end"],
                                "length": n - eocd["end"],
                                "reason": "trailing data after end of "
                                          "central directory"})
        pos = n

    if not cd_report["found"] and eocd_info is not None:
        cd_report.update(found=True, offset=eocd_info["offset"],
                         entries=eocd_info["entries"])
        cd_report["notes"].append(
            "end of central directory exists but is not reachable by "
            "sequential scan")

    seen: dict[str, int] = {}
    out_entries = []
    for e in entries:
        seq = seen.get(e.name, 0)
        seen[e.name] = seq + 1
        out_entries.append({
            "index": e.index,
            "name": e.name,
            "name_seq": seq,
            "offset": e.offset,
            "end_offset": e.end_offset,
            "header_size": e.header_size,
            "data_offset": e.data_offset,
            "method": {0: "stored", 8: "deflate"}[e.method],
            "compressed_size": e.compressed_size,
            "uncompressed_size": e.uncompressed_size,
            "crc32": f"{e.crc32:08x}",
            "sha256": e.sha256,
            "descriptor": e.descriptor,
            "status": e.status,
        })

    return {
        "entries": out_entries,
        "damaged_regions": damaged,
        "ambiguities": amb,
        "central_directory": cd_report,
        "eocd_found": cd_report["found"],
        "truncated": not cd_report["found"],
        "entry_count": len(out_entries),
        "certain_count": sum(1 for e in out_entries
                             if e["status"] == "certain"),
        "candidate_count": sum(1 for e in out_entries
                               if e["status"] == "candidate"),
        "expanded_bytes": ctx.total_expanded,
    }
