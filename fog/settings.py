import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/iiot.db")
    jwt_secret: str = os.getenv("FOG_JWT_SECRET", "development-only-change-me")
    jwt_algorithm: str = "HS256"
    token_ttl_seconds: int = int(os.getenv("TOKEN_TTL_SECONDS", "120"))
    zone_id: str = "zone-1"


settings = Settings()

