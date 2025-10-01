import os
import json

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config", "server.json")

with open(CONFIG_PATH) as f:
    config_data = json.load(f)

SECRET_KEY = os.getenv("SECRET_KEY", config_data.get("SECRET_KEY", "fallback-secret"))
ALGORITHM = os.getenv("ALGORITHM", config_data.get("ALGORITHM", "HS256"))
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", config_data.get("ACCESS_TOKEN_EXPIRE_MINUTES", 30)))
