"""Damaged-ZIP recovery engine.

Recovery is driven purely by local file headers, DEFLATE stream
boundaries, data descriptors (with or without the ``PK\\x07\\x08``
signature) and CRC-32 / length cross-checks.  The central directory is
never used for recovery (it may be missing or truncated); it is parsed
afterwards for reporting only.

Design rules required by the service contract:

* scanning resumes after damaged segments, but only entries that form a
  continuously verifiable chain from the start of the archive are marked
  ``confirmed``; anything past a bad segment is a ``candidate``;
* a local-header-looking byte sequence inside arbitrary data is never
  trusted on its signature alone -- a candidate entry is accepted only
  after its compressed stream, data descriptor and CRC-32/length all
  verify;
* when more than one layout verifies (e.g. several plausible data
  descriptors for one STORED entry) the ambiguity is reported on the
  entry and the verification chain is considered broken from there on;
* encrypted and ZIP64 inputs are rejected as a whole, as is any input
  whose cumulative expanded output exceeds the configured limit.
"""

from __future__ import annotations

import binascii
import hashlib
import mmap
import os
import struct
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

LFH_SIG = b"PK\x03\x04"
CD_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
DD_SIG = b"PK\x07\x08"
ZIP64_EOCD_SIG = b"PK\x06\x06"
ZIP64_LOCATOR_SIG = b"PK\x06\x07"

CHUNK = 1024 * 1024  # 1 MiB streaming quantum

STORED = 0
DEFLATE = 8
METHOD_NAMES = {STORED: "stored", DEFLATE: "deflate"}

FLAG_ENCRYPTED = 0x0001
FLAG_DESCRIPTOR = 0x0008
FLAG_UTF8 = 0x0800

ZIP64_EXTRA_ID = 0x0001
U32_MAX = 0xFFFFFFFF
U16_MAX = 0xFFFF

EOCD_SEARCH_WINDOW = 65536 + 22  # max EOCD comment + fixed part


class RejectError(Exception):
    """Fatal condition: reject the whole submission, keep nothing."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class _Candidate:
    """One verifiable way to close an entry."""

    q: int  # offset of the data descriptor (== end of compressed data)
    end: int  # offset just past the entry (data + descriptor)
    kind: str  # 'signature' | 'nosignature' | 'header' | 'missing'
    crc: int
    csize: int
    usize: int


@dataclass
class _Entry:
    n: int = -1
    name: str = ""
    name_seq: int = 0
    offset: int = 0
    data_offset: int = 0
    end: int = 0
    method: str = ""
    flags: int = 0
    crc32: int = 0
    compressed_size: int = 0
    size: int = 0
    sha256: str = ""
    status: str = "candidate"
    descriptor: str = "none"
    notes: List[str] = field(default_factory=list)
    ambiguity: List[dict] = field(default_factory=list)
    payload_tmp: Optional[str] = None  # temp payload path, renamed on accept
    payload_rel: Optional[str] = None  # path relative to the job directory


class _Budget:
    """Cumulative expanded-bytes limiter (zip-bomb protection)."""

    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    def charge(self, n: int) -> None:
        self.used += n
        if self.used > self.limit:
            raise RejectError(
                "expand_limit_exceeded",
                "cumulative expanded data exceeds the limit of "
                f"{self.limit} bytes",
            )


class _PayloadWriter:
    """Streams recovered original bytes to a temp file, hashing on the fly."""

    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "wb")
        self._sha = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> None:
        self._f.write(data)
        self._sha.update(data)
        self.size += len(data)

    @property
    def sha256(self) -> str:
        return self._sha.hexdigest()

    def close(self) -> None:
        self._f.close()


def _has_zip64_extra(extra: bytes) -> bool:
    p = 0
    while p + 4 <= len(extra):
        hid, hlen = struct.unpack("<HH", extra[p : p + 4])
        if hid == ZIP64_EXTRA_ID:
            return True
        p += 4 + hlen
    return False


class Recoverer:
    def __init__(self, workdir: str, max_expand_bytes: int):
        self.workdir = workdir
        self.tmp_dir = os.path.join(workdir, "tmp")
        self.entries_dir = os.path.join(workdir, "entries")
        os.makedirs(self.tmp_dir, exist_ok=True)
        self.budget = _Budget(max_expand_bytes)
        self.entries: List[_Entry] = []
        self.damaged: List[dict] = []
        self.cd: dict = {
            "status": "missing",
            "cd_offset": None,
            "cd_entries": 0,
            "eocd_offset": None,
            "eocd_entries": None,
            "notes": [],
        }
        self.mm: Optional[mmap.mmap] = None
        self.size = 0
        self._chain = True
        self._last_fail = "unrecognized data"
        self._name_counts: dict = {}
        self._payload_seq = 0

    # ------------------------------------------------------------------
    # top-level walk
    # ------------------------------------------------------------------
    def run(self) -> None:
        mm = self.mm
        assert mm is not None
        pos = 0
        while pos < self.size:
            sig = mm[pos : pos + 4]
            if sig == LFH_SIG:
                ent = self._try_entry(pos, strict=True, write_payload=True,
                                      probe_cont=True)
                if ent is not None:
                    self._accept(ent)
                    if ent.ambiguity:
                        self._chain = False
                    pos = ent.end
                    continue
                self._chain = False
                pos = self._skip_damaged(pos, self._last_fail)
                continue
            if sig == CD_SIG:
                self._parse_central_directory(pos)
                break
            if sig == EOCD_SIG:
                self._parse_eocd(pos, aligned=True)
                break
            if sig in (ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG):
                raise RejectError("zip64", f"ZIP64 structure at offset {pos}")
            self._chain = False
            pos = self._skip_damaged(pos, "unrecognized data")
        if self.cd["eocd_offset"] is None and self.cd["cd_offset"] is None:
            self._trailing_eocd_scan()

    def report(self) -> dict:
        entries = []
        for e in self.entries:
            item = {
                "n": e.n,
                "name": e.name,
                "name_seq": e.name_seq,
                "offset": e.offset,
                "data_offset": e.data_offset,
                "end_offset": e.end,
                "method": e.method,
                "flags": e.flags,
                "compressed_size": e.compressed_size,
                "size": e.size,
                "crc32": f"{e.crc32 & 0xFFFFFFFF:08x}",
                "sha256": e.sha256,
                "status": e.status,
                "descriptor": e.descriptor,
                "notes": e.notes,
            }
            if e.ambiguity:
                item["ambiguity"] = e.ambiguity
            entries.append(item)
        cd = dict(self.cd)
        cd["recovered_entries"] = len(self.entries)
        summary = {
            "total_entries": len(self.entries),
            "confirmed": sum(1 for e in self.entries if e.status == "confirmed"),
            "candidate": sum(1 for e in self.entries if e.status == "candidate"),
            "ambiguous": sum(1 for e in self.entries if e.ambiguity),
            "damaged_ranges": len(self.damaged),
            "damaged_bytes": sum(r["length"] for r in self.damaged),
            "recovered_bytes": sum(e.size for e in self.entries),
            "expanded_bytes": self.budget.used,
        }
        return {
            "central_directory": cd,
            "summary": summary,
            "entries": entries,
            "damaged_ranges": self.damaged,
        }

    # ------------------------------------------------------------------
    # damaged-segment handling
    # ------------------------------------------------------------------
    def _skip_damaged(self, start: int, reason: str) -> int:
        """Record a damaged range from ``start`` and resynchronise.

        Every ``PK\\x03\\x04`` occurrence is probed, but a candidate is
        accepted only when the whole entry verifies -- a signature alone
        is never enough.
        """
        mm = self.mm
        assert mm is not None
        p = start + 1
        while True:
            q = mm.find(LFH_SIG, p)
            if q < 0:
                self._add_damaged(start, self.size - start, reason)
                return self.size
            ent = self._try_entry(q, strict=False, write_payload=True,
                                  probe_cont=True)
            if ent is not None:
                self._add_damaged(start, q - start, reason)
                self._accept(ent)
                return ent.end
            p = q + 1

    def _add_damaged(self, offset: int, length: int, reason: str) -> None:
        if length <= 0:
            return
        self.damaged.append(
            {"offset": offset, "length": length, "reason": reason}
        )

    def _accept(self, ent: _Entry) -> None:
        ent.n = len(self.entries)
        ent.name_seq = self._name_counts.get(ent.name, 0) + 1
        self._name_counts[ent.name] = ent.name_seq
        if self._chain and not ent.ambiguity:
            ent.status = "confirmed"
        else:
            ent.status = "candidate"
        os.makedirs(self.entries_dir, exist_ok=True)
        if ent.payload_tmp is not None:
            rel = f"entries/{ent.n}.bin"
            os.replace(ent.payload_tmp, os.path.join(self.workdir, rel))
            ent.payload_rel = rel
            ent.payload_tmp = None
        self.entries.append(ent)

    # ------------------------------------------------------------------
    # entry parsing / validation
    # ------------------------------------------------------------------
    def _fail(self, reason: str) -> None:
        self._last_fail = reason

    def _try_entry(self, pos: int, *, strict: bool, write_payload: bool,
                   probe_cont: bool) -> Optional[_Entry]:
        """Try to parse and fully verify one entry at ``pos``.

        ``strict`` is true only when ``pos`` is exactly where the walk
        expects an entry; strict mode turns encryption/ZIP64 markers into
        whole-order rejections.  Probed candidates (possibly fake headers
        inside foreign data) merely fail instead.
        """
        mm = self.mm
        assert mm is not None
        if pos + 30 > self.size:
            self._fail("truncated local file header")
            return None
        (_sig, _ver, flags, method, _mt, _md, crc, csize, usize,
         nlen, xlen) = struct.unpack("<4s5H3I2H", mm[pos : pos + 30])
        data_start = pos + 30 + nlen + xlen
        if data_start > self.size:
            self._fail("local file header extends past end of data")
            return None
        if flags & FLAG_ENCRYPTED:
            if strict:
                raise RejectError(
                    "encrypted",
                    f"entry at offset {pos} is encrypted (general purpose "
                    "flag bit 0 set)",
                )
            self._fail("encrypted entry")
            return None
        extra = mm[pos + 30 + nlen : data_start]
        if csize == U32_MAX or usize == U32_MAX or _has_zip64_extra(extra):
            if strict:
                raise RejectError(
                    "zip64", f"entry at offset {pos} uses ZIP64 structures"
                )
            self._fail("zip64 entry")
            return None
        if method not in METHOD_NAMES:
            self._fail(f"unsupported compression method {method}")
            return None
        if not strict and nlen == 0:
            # probed candidates must carry a name; cuts false positives
            self._fail("empty entry name")
            return None
        raw_name = bytes(mm[pos + 30 : pos + 30 + nlen])
        enc = "utf-8" if flags & FLAG_UTF8 else "cp437"
        name = raw_name.decode(enc, errors="replace")

        ent = _Entry(
            offset=pos,
            data_offset=data_start,
            method=METHOD_NAMES[method],
            flags=flags,
            crc32=crc,
            name=name,
        )
        has_dd = bool(flags & FLAG_DESCRIPTOR)
        if method == DEFLATE:
            ok = self._recover_deflate(ent, crc, csize, usize, has_dd,
                                       write_payload, probe_cont)
        else:
            ok = self._recover_stored(ent, crc, csize, usize, has_dd,
                                      write_payload, probe_cont)
        return ent if ok else None

    # ------------------------- DEFLATE ---------------------------------
    def _recover_deflate(self, ent: _Entry, crc: int, csize: int,
                         usize: int, has_dd: bool, write_payload: bool,
                         probe_cont: bool) -> bool:
        mm = self.mm
        assert mm is not None
        size = self.size
        writer = self._new_writer() if write_payload else None
        d = zlib.decompressobj(-15)
        p = ent.data_offset
        fed = 0
        out_crc = 0
        out_len = 0
        try:
            while p < size and not d.eof:
                chunk = bytes(mm[p : p + CHUNK])
                out = d.decompress(chunk)
                fed += len(chunk)
                p += len(chunk)
                if out:
                    self.budget.charge(len(out))
                    out_crc = binascii.crc32(out, out_crc)
                    out_len += len(out)
                    if writer is not None:
                        writer.write(out)
        except zlib.error as exc:
            self._cleanup_writer(writer)
            self._fail(f"deflate stream error: {exc}")
            return False
        if not d.eof:
            self._cleanup_writer(writer)
            self._fail("truncated deflate stream")
            return False
        consumed = fed - len(d.unused_data)
        dd_off = ent.data_offset + consumed
        ent.crc32 = out_crc
        ent.compressed_size = consumed
        ent.size = out_len

        if has_dd:
            cands: List[_Candidate] = []
            if dd_off + 16 <= size and mm[dd_off : dd_off + 4] == DD_SIG:
                c, cs, us = struct.unpack("<3I", mm[dd_off + 4 : dd_off + 16])
                cands.append(_Candidate(dd_off, dd_off + 16, "signature",
                                        c, cs, us))
            if dd_off + 12 <= size:
                c, cs, us = struct.unpack("<3I", mm[dd_off : dd_off + 12])
                cands.append(_Candidate(dd_off, dd_off + 12, "nosignature",
                                        c, cs, us))
            valid = [c for c in cands
                     if c.crc == out_crc and c.csize == consumed
                     and c.usize == out_len]
            if not valid and (crc or usize):
                # some writers fill the local header even when bit 3 is set
                if (crc == out_crc and usize == out_len
                        and csize in (0, consumed)):
                    valid = [_Candidate(dd_off, dd_off, "missing",
                                        crc, consumed, usize)]
                    ent.notes.append(
                        "data descriptor missing; verified against the "
                        "local header"
                    )
            if not valid:
                self._cleanup_writer(writer)
                self._fail("no matching data descriptor")
                return False
        else:
            if crc != out_crc or usize != out_len:
                self._cleanup_writer(writer)
                self._fail("CRC-32/size mismatch with local header")
                return False
            if csize != consumed:
                ent.notes.append(
                    f"local header compressed size {csize} disagrees with "
                    f"the deflate stream boundary ({consumed})"
                )
            valid = [_Candidate(dd_off, dd_off, "header",
                                crc, consumed, usize)]
        chosen = self._choose(valid, probe_cont)
        return self._finalize(ent, valid, chosen, writer)

    # ------------------------- STORED ----------------------------------
    def _recover_stored(self, ent: _Entry, crc: int, csize: int,
                        usize: int, has_dd: bool, write_payload: bool,
                        probe_cont: bool) -> bool:
        mm = self.mm
        assert mm is not None
        size = self.size
        data_start = ent.data_offset
        if not has_dd or csize:
            # extent known from the local header
            if csize != usize:
                self._fail("stored entry with differing "
                           "compressed/uncompressed sizes")
                return False
            end0 = data_start + csize
            if end0 > size:
                self._fail("stored data truncated")
                return False
            writer = self._new_writer() if write_payload else None
            actual_crc = self._stream_region(data_start, end0, writer)
            if actual_crc != crc:
                self._cleanup_writer(writer)
                self._fail("CRC-32 mismatch with local header")
                return False
            ent.compressed_size = csize
            ent.size = usize
            cands: List[_Candidate] = []
            if has_dd:
                if end0 + 16 <= size and mm[end0 : end0 + 4] == DD_SIG:
                    c2, cs2, us2 = struct.unpack(
                        "<3I", mm[end0 + 4 : end0 + 16])
                    if (c2, cs2, us2) == (crc, csize, usize):
                        cands.append(_Candidate(end0, end0 + 16, "signature",
                                                c2, cs2, us2))
                if end0 + 12 <= size:
                    c2, cs2, us2 = struct.unpack("<3I", mm[end0 : end0 + 12])
                    if (c2, cs2, us2) == (crc, csize, usize):
                        cands.append(_Candidate(end0, end0 + 12,
                                                "nosignature", c2, cs2, us2))
                if not cands:
                    cands.append(_Candidate(end0, end0, "missing",
                                            crc, csize, usize))
                    ent.notes.append(
                        "data descriptor missing; verified against the "
                        "local header"
                    )
            else:
                cands.append(_Candidate(end0, end0, "header",
                                        crc, csize, usize))
            chosen = self._choose(cands, probe_cont)
            return self._finalize(ent, cands, chosen, writer)

        # bit 3 set and sizes unknown: scan for a verifiable descriptor
        cands = self._stored_dd_candidates(data_start)
        valid = self._validate_stored_dd(data_start, cands)
        if not valid:
            self._fail("no verifiable data descriptor found")
            return False
        chosen = self._choose(valid, probe_cont)
        writer = self._new_writer() if write_payload else None
        self._stream_region(data_start, chosen.q, writer)
        ent.crc32 = chosen.crc
        ent.compressed_size = chosen.q - data_start
        ent.size = chosen.q - data_start
        return self._finalize(ent, valid, chosen, writer)

    def _stored_dd_candidates(self, data_start: int) -> List[_Candidate]:
        """All structurally plausible descriptor positions after data_start."""
        mm = self.mm
        assert mm is not None
        size = self.size
        cands: List[_Candidate] = []
        # signed descriptors may appear anywhere
        p = data_start
        while True:
            q = mm.find(DD_SIG, p)
            if q < 0 or q + 16 > size:
                break
            c, cs, us = struct.unpack("<3I", mm[q + 4 : q + 16])
            cands.append(_Candidate(q, q + 16, "signature", c, cs, us))
            p = q + 4
        # unsigned descriptors are only detectable immediately before
        # another structure (local header / central directory / EOCD) or
        # at end of file
        boundaries = {size}
        for sig in (LFH_SIG, CD_SIG, EOCD_SIG):
            p = data_start
            while True:
                h = mm.find(sig, p)
                if h < 0:
                    break
                boundaries.add(h)
                p = h + 1
        for h in boundaries:
            q = h - 12
            if q < data_start:
                continue
            c, cs, us = struct.unpack("<3I", mm[q : q + 12])
            cands.append(_Candidate(q, h, "nosignature", c, cs, us))
        return cands

    def _validate_stored_dd(self, data_start: int,
                            cands: List[_Candidate]) -> List[_Candidate]:
        """Keep candidates whose CRC-32 and lengths actually verify.

        A single incremental CRC walk over the data region serves every
        candidate, so the cost stays linear in the region size.
        """
        valid = []
        crc = 0
        p = data_start
        mm = self.mm
        assert mm is not None
        for c in sorted(cands, key=lambda c: c.q):
            if c.csize != c.q - data_start or c.usize != c.csize:
                continue
            while p < c.q:
                step = min(CHUNK, c.q - p)
                buf = mm[p : p + step]
                crc = binascii.crc32(buf, crc)
                self.budget.charge(len(buf))
                p += step
            if crc == c.crc:
                valid.append(c)
        return valid

    # ------------------------- shared ----------------------------------
    def _choose(self, valid: List[_Candidate], probe_cont: bool) -> _Candidate:
        """Pick the split whose end lands on a valid continuation.

        All verifiable splits are reported as ambiguity by the caller;
        this only decides which one the walk follows.
        """
        best = None
        best_score = -1
        for c in sorted(valid, key=lambda c: c.end):
            score = self._continuation_score(c.end) if probe_cont else 0
            if score > best_score:
                best, best_score = c, score
        return best

    def _continuation_score(self, end: int) -> int:
        mm = self.mm
        assert mm is not None
        if end >= self.size:
            return 1
        sig = mm[end : end + 4]
        if sig in (CD_SIG, EOCD_SIG):
            return 1
        if sig == LFH_SIG:
            probe = self._try_entry(end, strict=False, write_payload=False,
                                    probe_cont=False)
            if probe is not None:
                return 1
        return 0

    def _finalize(self, ent: _Entry, valid: List[_Candidate],
                  chosen: _Candidate, writer: Optional[_PayloadWriter]) -> bool:
        ent.end = chosen.end
        ent.descriptor = "none" if chosen.kind == "header" else chosen.kind
        if len(valid) > 1:
            ent.ambiguity = [
                {"end_offset": c.end, "descriptor": c.kind}
                for c in sorted(valid, key=lambda c: c.end)
            ]
            ent.notes.append(
                "multiple verifiable layouts exist; the walk follows the "
                "one with a valid continuation"
            )
        if writer is not None:
            writer.close()
            ent.sha256 = writer.sha256
            ent.payload_tmp = writer.path
        return True

    def _stream_region(self, start: int, end: int,
                       writer: Optional[_PayloadWriter]) -> int:
        mm = self.mm
        assert mm is not None
        crc = 0
        p = start
        while p < end:
            step = min(CHUNK, end - p)
            buf = mm[p : p + step]
            self.budget.charge(len(buf))
            crc = binascii.crc32(buf, crc)
            if writer is not None:
                writer.write(buf)
            p += step
        return crc

    def _new_writer(self) -> _PayloadWriter:
        path = os.path.join(self.tmp_dir, f"payload-{self._payload_seq}.bin")
        self._payload_seq += 1
        return _PayloadWriter(path)

    def _cleanup_writer(self, writer: Optional[_PayloadWriter]) -> None:
        if writer is None:
            return
        try:
            writer.close()
        finally:
            try:
                os.unlink(writer.path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # central directory (reporting only)
    # ------------------------------------------------------------------
    def _parse_central_directory(self, pos: int) -> None:
        mm = self.mm
        assert mm is not None
        count = 0
        p = pos
        truncated = False
        while mm[p : p + 4] == CD_SIG:
            if p + 46 > self.size:
                truncated = True
                break
            fields = struct.unpack("<4s6H3I5H2I", mm[p : p + 46])
            (_sig, _vm, _vn, _flags, _m, _t, _d, _crc, csize, usize,
             nlen, xlen, clen, _disk, _ia, _xa, lho) = fields
            if p + 46 + nlen + xlen + clen > self.size:
                truncated = True
                break
            extra = mm[p + 46 + nlen : p + 46 + nlen + xlen]
            if (csize == U32_MAX or usize == U32_MAX or lho == U32_MAX
                    or _has_zip64_extra(extra)):
                raise RejectError(
                    "zip64", "central directory uses ZIP64 structures")
            count += 1
            p += 46 + nlen + xlen + clen
        self.cd["cd_offset"] = pos
        self.cd["cd_entries"] = count
        self.cd["cd_end_offset"] = p
        if mm[p : p + 4] in (ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG):
            raise RejectError("zip64", f"ZIP64 structure at offset {p}")
        if mm[p : p + 4] == EOCD_SIG:
            self._parse_eocd(p, aligned=True)
        else:
            truncated = True
            self.cd["notes"].append(
                "end-of-central-directory record not found after the "
                "central directory"
            )
        if truncated:
            self.cd["status"] = "truncated"
        elif (self.cd["eocd_entries"] is not None
                and self.cd["eocd_entries"] != count):
            self.cd["status"] = "truncated"
            self.cd["notes"].append(
                "EOCD entry count disagrees with the parsed central "
                "directory"
            )
        else:
            self.cd["status"] = "present"

    def _parse_eocd(self, pos: int, aligned: bool) -> None:
        mm = self.mm
        assert mm is not None
        if pos + 22 > self.size:
            self.cd["status"] = "truncated"
            self.cd["notes"].append("truncated end-of-central-directory "
                                    "record")
            return
        (_sig, d1, d2, n1, n2, cd_size, cd_off,
         comlen) = struct.unpack("<4s4H2IH", mm[pos : pos + 22])
        if aligned and (d1 == U16_MAX or d2 == U16_MAX or n1 == U16_MAX
                        or n2 == U16_MAX or cd_size == U32_MAX
                        or cd_off == U32_MAX):
            raise RejectError(
                "zip64", "end-of-central-directory uses ZIP64 sentinels")
        self.cd["eocd_offset"] = pos
        self.cd["eocd_entries"] = n2
        if self.cd["cd_offset"] is None:
            # EOCD reached without a central directory in the walk
            self.cd["status"] = "present" if n2 == 0 else "missing"
            if n2:
                self.cd["notes"].append(
                    "EOCD announces a central directory that is not "
                    "present in the data"
                )

    def _trailing_eocd_scan(self) -> None:
        """Best-effort EOCD lookup when the walk never reached one."""
        mm = self.mm
        assert mm is not None
        start = max(0, self.size - EOCD_SEARCH_WINDOW)
        idx = mm.rfind(EOCD_SIG, start)
        if idx < 0 or idx + 22 > self.size:
            return
        (_sig, _d1, _d2, _n1, n2, _cs, _co,
         _cl) = struct.unpack("<4s4H2IH", mm[idx : idx + 22])
        self.cd["eocd_offset"] = idx
        self.cd["eocd_entries"] = n2
        self.cd["notes"].append(
            "end-of-central-directory found without a readable central "
            "directory"
        )


def run_recovery(upload_path: str, workdir: str, max_expand_bytes: int) -> dict:
    """Recover ``upload_path``; payloads and metadata land in ``workdir``.

    Raises RejectError for whole-order rejections; the caller is
    responsible for wiping ``workdir`` in that case.
    """
    rec = Recoverer(workdir, max_expand_bytes)
    size = os.path.getsize(upload_path)
    if size > 0:
        with open(upload_path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                rec.mm = mm
                rec.size = size
                rec.run()
            finally:
                mm.close()
    return rec.report()
