# server/api/utils/keys.py
"""
KeyManager: simple, thread-safe key store with file persistence for signing key rotation.

- Stores mapping kid -> key material (symmetric secret or PEM string).
- Persists to a file at project root .signing_keys.json when changed.
- Supports: get_key(kid), add_key(kid, key), remove_key(kid), list_keys(),
  set_preferred(kid), get_preferred().
- Safe defaults: loads SIGNING_KEYS_JSON env if present (JSON mapping).
- Not a replacement for a secure KMS; use KMS in production and call KeyManager from deployment hooks.
"""
from __future__ import annotations
import os
import json
import threading
from pathlib import Path
from typing import Dict, Optional

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PERSIST_FILE = _PROJECT_ROOT / ".signing_keys.json"
_ENV_RAW = os.environ.get("SIGNING_KEYS_JSON", "")

_lock = threading.RLock()


class KeyManager:
    def __init__(self):
        self._keys: Dict[str, str] = {}
        self._preferred: Optional[str] = None
        self._load_from_env_or_file()

    def _load_from_env_or_file(self):
        with _lock:
            if _ENV_RAW:
                try:
                    data = json.loads(_ENV_RAW)
                    if isinstance(data, dict):
                        self._keys = {str(k): str(v) for k, v in data.items()}
                except Exception:
                    self._keys = {}
            elif _PERSIST_FILE.exists():
                try:
                    data = json.loads(_PERSIST_FILE.read_text(encoding="utf-8") or "{}")
                    self._keys = {str(k): str(v) for k, v in data.get("keys", {}).items()}
                    self._preferred = data.get("preferred")
                except Exception:
                    self._keys = {}
                    self._preferred = None
            else:
                self._keys = {}
                self._preferred = None

            if not self._preferred and self._keys:
                # deterministic choice
                self._preferred = next(iter(self._keys.keys()))

    def _persist(self):
        try:
            payload = {"keys": self._keys, "preferred": self._preferred}
            _PERSIST_FILE.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def get_key(self, kid: Optional[str]) -> Optional[str]:
        with _lock:
            if kid:
                k = self._keys.get(kid)
                if k:
                    return k
            if self._preferred:
                return self._keys.get(self._preferred)
            # fallback: single key if present
            if len(self._keys) == 1:
                return next(iter(self._keys.values()))
            return None

    def add_key(self, kid: str, key_material: str, make_preferred: bool = False) -> bool:
        with _lock:
            self._keys[str(kid)] = str(key_material)
            if make_preferred or not self._preferred:
                self._preferred = str(kid)
            self._persist()
            return True

    def remove_key(self, kid: str) -> bool:
        with _lock:
            kid = str(kid)
            if kid in self._keys:
                del self._keys[kid]
                if self._preferred == kid:
                    self._preferred = next(iter(self._keys.keys()), None)
                self._persist()
                return True
            return False

    def list_keys(self) -> Dict[str, str]:
        with _lock:
            return dict(self._keys)

    def get_preferred(self) -> Optional[str]:
        with _lock:
            return self._preferred

    def set_preferred(self, kid: str) -> bool:
        with _lock:
            if kid in self._keys:
                self._preferred = kid
                self._persist()
                return True
            return False

    def rotate_key(self, new_kid: str, new_key_material: str, make_preferred: bool = True) -> bool:
        """
        Add a new key and optionally make it preferred. This is the runtime rotation primitive.
        For production, persist keys in a KMS and coordinate rotation across services.
        """
        return self.add_key(new_kid, new_key_material, make_preferred=make_preferred)


# Singleton manager for app
_key_manager = KeyManager()


def get_key_manager() -> KeyManager:
    return _key_manager
