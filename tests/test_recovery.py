"""Tests for the damaged-ZIP recovery API."""
import io
import json
import os
import sqlite3
import struct
import zipfile
import zlib

import pytest
from starlette.testclient import TestClient

from app import config, db
from app.main import app

LOCAL_SIG = 0x04034B50
CD_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
DD_SIG = b"PK\x07\x08"


# ---------------------------------------------------------------- helpers

def deflate_raw(content: bytes) -> bytes:
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    return co.compress(content) + co.flush()


def local_entry(name: str, content: bytes, method: int = 8,
                descriptor: bool = False, dd_sig: bool = True,
                flags_extra: int = 0, crc_override=None,
                csize_override=None, usize_override=None) -> bytes:
    """Build one local file entry (no central directory)."""
    name_b = name.encode()
    comp = deflate_raw(content) if method == 8 else content
    crc = zlib.crc32(content)
    flags = (0x08 if descriptor else 0) | flags_extra
    if descriptor:
        hdr = struct.pack("<I5H3I2H", LOCAL_SIG, 20, flags, method, 0, 0,
                          0, 0, 0, len(name_b), 0)
        dd = (DD_SIG if dd_sig else b"") + struct.pack(
            "<III", crc, len(comp), len(content))
        return hdr + name_b + comp + dd
    hdr = struct.pack(
        "<I5H3I2H", LOCAL_SIG, 20, flags, method, 0, 0,
        crc if crc_override is None else crc_override,
        len(comp) if csize_override is None else csize_override,
        len(content) if usize_override is None else usize_override,
        len(name_b), 0)
    return hdr + name_b + comp


def central_directory(metas) -> bytes:
    """metas: list of dicts with name/method/crc/csize/usize/offset."""
    cd = b""
    for m in metas:
        name_b = m["name"].encode()
        cd += struct.pack(
            "<I6H3I5H2I", CD_SIG, 20, 20, m.get("flags", 0), m["method"],
            0, 0, m["crc"], m["csize"], m["usize"], len(name_b), 0, 0,
            0, 0, 0, m["offset"]) + name_b
    eocd = struct.pack("<I4H2IH", EOCD_SIG, 0, 0, len(metas), len(metas),
                       len(cd), metas[0]["cd_offset"], 0)
    return cd + eocd


def post(client, data: bytes, **params):
    return client.post("/recover", content=data,
                       headers={"content-type": "application/zip"},
                       params=params)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 256 * 1024 * 1024)
    monkeypatch.setattr(config, "MAX_EXPANDED_BYTES", 1 << 30)
    db.init()
    with TestClient(app) as c:
        c.data_dir = tmp_path
        yield c


def archive_count(client):
    conn = sqlite3.connect(config.db_path())
    try:
        return conn.execute("SELECT COUNT(*) FROM archives").fetchone()[0]
    finally:
        conn.close()


# ------------------------------------------------------------------ tests

def test_healthy_zipfile_archive(client):
    """A well-formed ZIP produced by the zipfile module."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("hello.txt", b"hello world" * 10)
        z.writestr("data.bin", os.urandom(2048),
                   compress_type=zipfile.ZIP_STORED)
        z.writestr("dir/nested.txt", b"nested content")
    r = post(client, buf.getvalue(), filename="healthy.zip")
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["entry_count"] == 3
    assert rep["certain_count"] == 3
    assert rep["candidate_count"] == 0
    assert rep["damaged_regions"] == []
    assert rep["central_directory"]["found"] is True
    assert rep["central_directory"]["consistent"] is True
    assert rep["eocd_found"] is True
    assert rep["truncated"] is False
    names = [e["name"] for e in rep["entries"]]
    assert names == ["hello.txt", "data.bin", "dir/nested.txt"]
    assert all(e["status"] == "certain" for e in rep["entries"])
    # offsets are listed in order
    offsets = [e["offset"] for e in rep["entries"]]
    assert offsets == sorted(offsets)

    # download entry 0 and compare bytes + headers
    d = client.get(f"/recover/{rep['id']}/entries/0")
    assert d.status_code == 200
    assert d.content == b"hello world" * 10
    assert d.headers["X-Entry-SHA256"] == rep["entries"][0]["sha256"]
    # report is persisted
    again = client.get(f"/recover/{rep['id']}")
    assert again.status_code == 200
    assert again.json()["id"] == rep["id"]


def test_recover_without_central_directory(client):
    """Local headers only: stored, deflate, and both descriptor flavours."""
    c0 = b"stored bytes, no descriptor"
    c1 = b"deflate bytes, no descriptor " * 3
    c2 = os.urandom(500)          # deflate + signed descriptor
    c3 = b"plain descriptor!"     # deflate + unsigned descriptor
    c4 = os.urandom(300)          # stored + signed descriptor
    blob = b"".join([
        local_entry("a.txt", c0, method=0),
        local_entry("b.txt", c1, method=8),
        local_entry("c.bin", c2, method=8, descriptor=True, dd_sig=True),
        local_entry("d.txt", c3, method=8, descriptor=True, dd_sig=False),
        local_entry("e.bin", c4, method=0, descriptor=True),
    ])
    r = post(client, blob)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["entry_count"] == 5
    assert rep["certain_count"] == 5
    assert rep["damaged_regions"] == []
    assert rep["eocd_found"] is False
    assert rep["truncated"] is True
    desc = [e["descriptor"] for e in rep["entries"]]
    assert desc == [None, None, "signature", "plain", "signature"]
    for i, content in enumerate([c0, c1, c2, c3, c4]):
        d = client.get(f"/recover/{rep['id']}/entries/{i}")
        assert d.status_code == 200
        assert d.content == content
        e = rep["entries"][i]
        import hashlib
        assert e["sha256"] == hashlib.sha256(content).hexdigest()
        assert e["uncompressed_size"] == len(content)


def test_truncated_archive(client):
    """Archive cut in the middle of the second entry's data."""
    e0 = local_entry("ok.txt", b"fine", method=0)
    e1 = local_entry("cut.bin", os.urandom(1000), method=8)
    blob = e0 + e1[:len(e1) // 2]
    r = post(client, blob)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["entry_count"] == 1
    assert rep["entries"][0]["name"] == "ok.txt"
    assert rep["entries"][0]["status"] == "certain"
    assert len(rep["damaged_regions"]) == 1
    reg = rep["damaged_regions"][0]
    assert reg["offset"] == len(e0)
    assert reg["offset"] + reg["length"] == rep["size"]
    assert rep["truncated"] is True


def test_corruption_in_the_middle(client):
    """A corrupted entry breaks the chain; later entries are candidates."""
    c0 = b"first entry"
    c1 = bytearray(os.urandom(200))
    c2 = b"third entry, still recoverable"
    e0 = local_entry("one.txt", c0, method=0)
    e1 = bytearray(local_entry("two.bin", bytes(c1), method=0))
    e1[-5] ^= 0xFF  # corrupt the stored payload -> crc mismatch
    e2 = local_entry("three.txt", c2, method=8)
    blob = e0 + bytes(e1) + e2
    r = post(client, blob)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["entry_count"] == 2
    assert rep["entries"][0]["name"] == "one.txt"
    assert rep["entries"][0]["status"] == "certain"
    assert rep["entries"][1]["name"] == "three.txt"
    assert rep["entries"][1]["status"] == "candidate"
    assert len(rep["damaged_regions"]) == 1
    reg = rep["damaged_regions"][0]
    assert reg["offset"] == len(e0)
    assert reg["offset"] + reg["length"] == len(e0) + len(e1)
    # candidate bytes are still downloadable
    d = client.get(f"/recover/{rep['id']}/entries/1")
    assert d.content == c2


def test_corrupt_deflate_stream_is_damage_not_error(client):
    """Garbage where a deflate stream should be -> damaged region, no 500."""
    e0 = local_entry("ok.txt", b"fine", method=0)
    bad = bytearray(local_entry("bad.bin", os.urandom(300), method=8))
    # overwrite the deflate payload with random bytes
    off = len(b"bad.bin") + 30
    bad[off:off + 100] = os.urandom(100)
    e2 = local_entry("after.txt", b"after", method=0)
    r = post(client, e0 + bytes(bad) + e2)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert [e["name"] for e in rep["entries"]] == ["ok.txt", "after.txt"]
    assert rep["entries"][1]["status"] == "candidate"
    assert len(rep["damaged_regions"]) == 1


def test_duplicate_names_keep_sequence(client):
    c_a, c_b, c_c = b"first", b"second", b"third"
    blob = (local_entry("same.txt", c_a, method=0)
            + local_entry("same.txt", c_b, method=0)
            + local_entry("other.txt", c_c, method=0)
            + local_entry("same.txt", c_a + c_b, method=0))
    r = post(client, blob)
    assert r.status_code == 200, r.text
    rep = r.json()
    seqs = [(e["name"], e["name_seq"]) for e in rep["entries"]]
    assert seqs == [("same.txt", 0), ("same.txt", 1),
                    ("other.txt", 0), ("same.txt", 2)]
    d = client.get(f"/recover/{rep['id']}/entries/1")
    assert d.content == c_b
    assert d.headers["X-Entry-Name-Seq"] == "1"


def test_encrypted_archive_rejected(client):
    blob = local_entry("secret.txt", b"data", method=0, flags_extra=0x0001)
    r = post(client, blob)
    assert r.status_code == 422
    assert "encrypt" in r.json()["detail"].lower()
    assert archive_count(client) == 0
    # no leftover entry payloads
    assert os.listdir(config.entries_root()) == []


def test_zip64_rejected(client):
    # local header with 0xFFFFFFFF sizes (ZIP64 sentinel)
    blob = local_entry("big.bin", b"x", method=0,
                       csize_override=0xFFFFFFFF)
    r = post(client, blob)
    assert r.status_code == 422
    assert "zip64" in r.json()["detail"].lower()
    assert archive_count(client) == 0

    # EOCD with ZIP64 sentinel values
    e0 = local_entry("a.txt", b"hello", method=0)
    eocd64 = struct.pack("<I4H2IH", EOCD_SIG, 0, 0, 1, 0xFFFF, 40, 0, 0)
    r = post(client, e0 + eocd64)
    assert r.status_code == 422
    assert "zip64" in r.json()["detail"].lower()


def test_upload_too_large_rejected(client, monkeypatch):
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 100)
    r = post(client, b"x" * 200)
    assert r.status_code == 413
    assert archive_count(client) == 0


def test_zip_bomb_rejected(client, monkeypatch):
    monkeypatch.setattr(config, "MAX_EXPANDED_BYTES", 1 << 20)  # 1 MiB
    blob = local_entry("bomb.bin", b"A" * (2 << 20), method=8)
    r = post(client, blob)
    assert r.status_code == 413
    assert archive_count(client) == 0
    assert os.listdir(config.entries_root()) == []


def test_ambiguous_stored_descriptor_reported(client):
    """Crafted STORED stream where two descriptor positions validate."""
    prefix = b"ABCD"
    fake_dd = DD_SIG + struct.pack("<III", zlib.crc32(prefix), 4, 4)
    suffix = b"remaining-data"
    content = prefix + fake_dd + suffix
    real_dd = DD_SIG + struct.pack("<III", zlib.crc32(content),
                                   len(content), len(content))
    name_b = b"amb.bin"
    hdr = struct.pack("<I5H3I2H", LOCAL_SIG, 20, 0x08, 0, 0, 0,
                      0, 0, 0, len(name_b), 0) + name_b
    blob = hdr + content + real_dd
    r = post(client, blob)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["entry_count"] == 1
    amb = rep["ambiguities"]
    assert len(amb) == 1
    assert amb[0]["kind"] == "stored_descriptor"
    assert amb[0]["alternatives"]
    # first (earliest) split was chosen
    assert rep["entries"][0]["uncompressed_size"] == 4
    d = client.get(f"/recover/{rep['id']}/entries/0")
    assert d.content == prefix


def test_fake_header_inside_data_not_an_entry(client):
    """A PK\x03\x04 signature inside file data must not become an entry."""
    content = b"prefix " + b"PK\x03\x04" + b"\x14\x00" + os.urandom(50)
    blob = local_entry("data.bin", content, method=0)
    r = post(client, blob)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["entry_count"] == 1
    assert rep["entries"][0]["status"] == "certain"
    d = client.get(f"/recover/{rep['id']}/entries/0")
    assert d.content == content


def test_resume_scan_skips_invalid_fake_headers(client):
    """Garbage containing an invalid PK\x03\x04 header is skipped."""
    e0 = local_entry("good.txt", b"good", method=0)
    fake = (struct.pack("<I5H3I2H", LOCAL_SIG, 20, 0, 99, 0, 0,
                        0, 0, 0, 4, 0) + b"name")  # method 99 -> invalid
    garbage = b"junk" + fake + b"more junk"
    e1 = local_entry("later.txt", b"later content", method=0)
    blob = e0 + garbage + e1
    r = post(client, blob)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert [e["name"] for e in rep["entries"]] == ["good.txt", "later.txt"]
    assert rep["entries"][1]["status"] == "candidate"
    assert rep["entries"][1]["offset"] == len(e0) + len(garbage)


def test_multiple_valid_resume_points_report_ambiguity(client):
    """Two verifiable headers inside/after a damaged region -> ambiguity."""
    e0 = local_entry("first.txt", b"one", method=0)
    inner = local_entry("inner.txt", b"two", method=0)  # valid but skipped
    e1 = local_entry("last.txt", b"three", method=0)
    blob = e0 + b"GARBAGE" + inner + e1
    r = post(client, blob)
    assert r.status_code == 200, r.text
    rep = r.json()
    names = [e["name"] for e in rep["entries"]]
    assert names == ["first.txt", "inner.txt", "last.txt"]
    assert rep["entries"][1]["status"] == "candidate"
    assert rep["entries"][2]["status"] == "candidate"
    kinds = [a["kind"] for a in rep["ambiguities"]]
    assert "resume_point" in kinds


def test_get_endpoints_404(client):
    assert client.get("/recover/deadbeef").status_code == 404
    blob = local_entry("a.txt", b"a", method=0)
    rep = post(client, blob).json()
    assert client.get(f"/recover/{rep['id']}/entries/5").status_code == 404
    assert client.get("/recover/nope/entries/0").status_code == 404


def test_empty_upload(client):
    r = post(client, b"")
    assert r.status_code == 200
    rep = r.json()
    assert rep["entry_count"] == 0
    assert rep["entries"] == []


def test_empty_zip_and_comment(client):
    """A valid empty archive (EOCD only) and one with an EOCD comment."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    r = post(client, buf.getvalue())
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["entry_count"] == 0
    assert rep["eocd_found"] is True
    assert rep["central_directory"]["consistent"] is True
    assert rep["damaged_regions"] == []

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"data")
        z.comment = b"archive comment"
    r = post(client, buf.getvalue())
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["entry_count"] == 1
    assert rep["eocd_found"] is True
    assert rep["damaged_regions"] == []


def test_trailing_garbage_after_eocd(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"hello")
    blob = buf.getvalue() + b"TRAILING"
    r = post(client, blob)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["entry_count"] == 1
    assert any(reg["offset"] + reg["length"] == rep["size"]
               for reg in rep["damaged_regions"])
