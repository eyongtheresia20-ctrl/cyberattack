import hashlib
import json
from datetime import datetime, timezone

def generate_sha256_hash(data: str | bytes | dict) -> str:
    """Generate SHA-256 integrity hash for data payload."""
    if isinstance(data, dict):
        data_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode('utf-8')).hexdigest()
    elif isinstance(data, str):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    elif isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()
    raise ValueError("Unsupported data type for hashing")

def format_timestamp(dt: datetime = None) -> str:
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.isoformat()
