import json
import os
import time
from typing import Dict, List
import valkey
from src.models import Document

class ValkeySessionTracker:
    """Uses Valkey Sorted Sets (ZSET) over mTLS + ACL auth for Aggregation Tracking."""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        username: str = "policy_service",
        password: str = None,
        use_tls: bool = True,
        cert_dir: str = "/certs",
        window_seconds: int = 3600
    ):
        password = password or os.getenv("VALKEY_PASSWORD")
        
        conn_kwargs = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "decode_responses": True,
        }

        if use_tls:
            conn_kwargs.update({
                "ssl": True,
                "ssl_certfile": os.path.join(cert_dir, "client.crt"),
                "ssl_keyfile": os.path.join(cert_dir, "client.key"),
                "ssl_ca_certs": os.path.join(cert_dir, "ca.crt"),
                "ssl_cert_reqs": "required",
            })

        self.client = valkey.Valkey(**conn_kwargs)
        self.window_seconds = window_seconds

    def _key(self, user_id: str) -> str:
        return f"policy:agg:history:{user_id}"

    def get_recent_activity(self, user_id: str) -> List[Dict]:
        key = self._key(user_id)
        now = time.time()
        cutoff = now - self.window_seconds

        pipe = self.client.pipeline()
        pipe.zremrangebyscore(key, "-inf", cutoff)
        pipe.zrangebyscore(key, cutoff, "+inf")
        _, raw_entries = pipe.execute()

        return [json.loads(entry) for entry in raw_entries]

    def log_retrieval(self, user_id: str, doc: Document):
        key = self._key(user_id)
        now = time.time()
        
        payload = json.dumps({
            "ts": now,
            "doc_id": doc.doc_id,
            "entities": list(doc.entities)
        })

        pipe = self.client.pipeline()
        pipe.zadd(key, {payload: now})
        pipe.expire(key, self.window_seconds)
        pipe.execute()
