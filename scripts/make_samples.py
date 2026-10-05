#!/usr/bin/env python3
"""Generate the sample (damaged) ZIP archives used in the README examples.

Usage:  python3 scripts/make_samples.py [output-dir]
"""

import binascii
import io
import os
import struct
import sys
import warnings
import zipfile
import zlib

OUT = sys.argv[1] if len(sys.argv) > 1 else "samples"


def crc32(b: bytes) -> int:
    return binascii.crc32(b) & 0xFFFFFFFF


def lfh(name: bytes, method: int, flags: int, crc: int, csize: int,
        usize: int) -> bytes:
    return struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method, 0, 0,
                       crc, csize, usize, len(name), 0) + name


def dd_sig(crc: int, csize: int, usize: int) -> bytes:
    return struct.pack("<IIII", 0x08074B50, crc, csize, usize)


def dd_nosig(crc: int, csize: int, usize: int) -> bytes:
    return struct.pack("<III", crc, csize, usize)


def stored(name: bytes, data: bytes) -> bytes:
    return lfh(name, 0, 0, crc32(data), len(data), len(data)) + data


def deflate_raw(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def main() -> None:
    os.makedirs(OUT, exist_ok=True)

    # 1. healthy archive (duplicate names on purpose)
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("notes.txt", b"first version\n",
                       compress_type=zipfile.ZIP_DEFLATED)
            z.writestr("notes.txt", b"second version\n",
                       compress_type=zipfile.ZIP_DEFLATED)
            z.writestr("logo.raw", bytes(range(256)) * 4,
                       compress_type=zipfile.ZIP_STORED)
    healthy = buf.getvalue()
    open(os.path.join(OUT, "healthy.zip"), "wb").write(healthy)

    # 2. same archive with the central directory cut off entirely
    cd_at = healthy.find(b"PK\x01\x02")
    open(os.path.join(OUT, "no-central.zip"), "wb").write(healthy[:cd_at])

    # 3. three stored entries, the middle one's data destroyed
    a = stored(b"a.txt", b"alpha: still intact\n")
    b_data = b"beta: this part is destroyed in the middle........\n"
    b = lfh(b"b.txt", 0, 0, crc32(b_data), len(b_data), len(b_data)) + b_data
    c = stored(b"c.txt", b"gamma: survived the crash\n")
    blob = bytearray(a + b + c)
    pos = len(a) + 30 + 6 + 20          # inside b's data
    blob[pos:pos + 16] = b"\xde\xad\xbe\xef" * 4
    open(os.path.join(OUT, "corrupted.zip"), "wb").write(bytes(blob))

    # 4. streaming-style archive: bit-3 descriptors, no central directory
    d1 = b"deflated payload, descriptor without signature\n" * 8
    comp = deflate_raw(d1)
    e1 = lfh(b"streamed.log", 8, 0x08, 0, 0, 0) + comp \
        + dd_nosig(crc32(d1), len(comp), len(d1))
    d2 = b"stored payload, descriptor with signature\n"
    e2 = lfh(b"raw.bin", 0, 0x08, 0, 0, 0) + d2 \
        + dd_sig(crc32(d2), len(d2), len(d2))
    open(os.path.join(OUT, "descriptors.zip"), "wb").write(e1 + e2)

    # 5. encrypted and zip64 samples (rejected as a whole)
    enc = lfh(b"secret.txt", 8, 0x01, 0, 0, 0) + b"\x00" * 32
    open(os.path.join(OUT, "encrypted.zip"), "wb").write(enc)
    z64 = lfh(b"big.bin", 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF) + b"\x00" * 16
    open(os.path.join(OUT, "zip64.zip"), "wb").write(z64)

    for f in sorted(os.listdir(OUT)):
        print(f"{f:20s} {os.path.getsize(os.path.join(OUT, f)):8d} bytes")


if __name__ == "__main__":
    main()
