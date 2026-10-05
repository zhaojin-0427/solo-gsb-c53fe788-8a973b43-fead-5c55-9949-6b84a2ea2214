"""Manual end-to-end sanity checks against a live uvicorn server."""
import io
import json
import os
import struct
import sys
import time
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def make_streamed_zip(path):
    """zipfile writing to an unseekable stream -> bit-3 descriptors."""

    class Unseekable(io.RawIOBase):
        def __init__(self, f):
            self.f = f

        def writable(self):
            return True

        def write(self, b):
            return self.f.write(b)

        def seekable(self):
            return False

    with open(path, "wb") as raw:
        zf = zipfile.ZipFile(Unseekable(raw), "w", zipfile.ZIP_DEFLATED)
        zf.writestr("streamed1.txt", b"streamed content " * 100)
        zf.writestr("streamed2.bin", os.urandom(4096))
        zf.writestr("empty.txt", b"")
        zf.close()


def make_large_zip(path, entries=8, mib_each=4):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(entries):
            z.writestr(f"big/{i}.bin", os.urandom(mib_each << 20))


def main():
    os.makedirs("/tmp/zr", exist_ok=True)
    make_streamed_zip("/tmp/zr/streamed.zip")
    make_large_zip("/tmp/zr/large.zip")

    # damage a copy: cut off the central directory + tail of last entry
    data = open("/tmp/zr/large.zip", "rb").read()
    cut = data[:-len(data) // 5]
    open("/tmp/zr/large_cut.zip", "wb").write(cut)

    # damage another: corrupt 1 MiB in the middle
    mid = bytearray(data)
    off = len(mid) // 2
    mid[off:off + (1 << 20)] = b"\x00" * (1 << 20)
    open("/tmp/zr/large_corrupt.zip", "wb").write(bytes(mid))

    import urllib.request

    def post(p):
        t0 = time.time()
        req = urllib.request.Request(
            "http://127.0.0.1:8123/recover?filename=" + os.path.basename(p),
            data=open(p, "rb").read(),
            headers={"content-type": "application/zip"})
        with urllib.request.urlopen(req) as r:
            rep = json.loads(r.read())
        dt = time.time() - t0
        print(f"== {os.path.basename(p)} ({os.path.getsize(p)} bytes) "
              f"in {dt:.2f}s")
        print(json.dumps({k: v for k, v in rep.items() if k != "entries"},
                         indent=2)[:1200])
        for e in rep["entries"][:4]:
            print("  ", e["index"], e["name"], e["status"],
                  e["uncompressed_size"], e["sha256"][:12])
        if len(rep["entries"]) > 4:
            print("   ...", len(rep["entries"]), "entries total")
        return rep

    rep1 = post("/tmp/zr/streamed.zip")
    assert rep1["entry_count"] == 3, rep1
    assert rep1["central_directory"]["consistent"] is True

    rep2 = post("/tmp/zr/large.zip")
    assert rep2["certain_count"] == rep2["entry_count"]

    rep3 = post("/tmp/zr/large_cut.zip")
    print("cut: certain", rep3["certain_count"], "candidates",
          rep3["candidate_count"], "damaged", rep3["damaged_regions"])

    rep4 = post("/tmp/zr/large_corrupt.zip")
    print("corrupt: certain", rep4["certain_count"], "candidates",
          rep4["candidate_count"], "damaged", rep4["damaged_regions"])

    # download one entry and verify sha
    import hashlib
    e = rep2["entries"][3]
    with urllib.request.urlopen(
            f"http://127.0.0.1:8123/recover/{rep2['id']}/entries/3") as r:
        body = r.read()
    assert hashlib.sha256(body).hexdigest() == e["sha256"]
    print("download sha256 verified for entry 3")
    print("ALL MANUAL CHECKS OK")


if __name__ == "__main__":
    main()
