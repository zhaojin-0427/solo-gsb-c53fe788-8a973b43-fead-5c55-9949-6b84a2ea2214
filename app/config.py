"""Runtime configuration, overridable via environment variables."""
import os

# Directory that holds the SQLite database, uploaded temp files and
# recovered entry payloads.  Inside docker this is a mounted volume.
DATA_DIR = os.environ.get("DATA_DIR", "data")

# Hard upload limit: 256 MiB by default.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(256 * 1024 * 1024)))

# Hard limit for the cumulative decompressed ("expanded") size of all
# entries of one archive: 1 GiB by default.  Protects against zip bombs.
MAX_EXPANDED_BYTES = int(os.environ.get("MAX_EXPANDED_BYTES", str(1024 * 1024 * 1024)))


def db_path() -> str:
    return os.path.join(DATA_DIR, "app.db")


def entries_root() -> str:
    return os.path.join(DATA_DIR, "entries")


def uploads_dir() -> str:
    return os.path.join(DATA_DIR, "uploads")
