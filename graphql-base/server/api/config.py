# server/api/config.py
import os
from datetime import timedelta

MAX_CHAIN_LIFETIME_SECONDS = int(os.environ.get("MAX_CHAIN_LIFETIME_SECONDS", 7 * 24 * 3600))
CHAIN_METADATA_TTL = MAX_CHAIN_LIFETIME_SECONDS + 3600  # extra hour grace before Redis auto-prune
