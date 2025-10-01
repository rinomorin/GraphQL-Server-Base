#!/usr/bin/env python3
# server/api/utils/keys_kms.py
"""
KMS adapter skeleton for KeyManager.
Implement get_secret_from_kms(kid) to fetch key material from your KMS (Azure Key Vault,
AWS Secrets Manager, HashiCorp Vault). This file provides a pluggable interface.
"""
from __future__ import annotations
import os
from typing import Optional


def get_secret_from_kms(kid: str) -> Optional[str]:
    """
    Return key material for kid from KMS. Return None if not found.

    Minimal default behavior: check SIGNING_KMS_{kid} env var for dev/test.
    Replace with real KMS client code for production.
    """
    if not kid:
        return None
    env_key = f"SIGNING_KMS_{kid}"
    return os.environ.get(env_key)
