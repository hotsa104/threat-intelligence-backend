"""
Centralized configuration using Pydantic Settings
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Main application settings"""

    # === FastAPI ===
    fastapi_port: int = Field(default=8000, alias="FASTAPI_PORT")
    fastapi_reload: bool = Field(default=True, alias="FASTAPI_RELOAD")

    # === Local Elasticsearch ===
    # 注: Raspberry Pi を使う場合は "192.168.1.100" に変更
    # または .env.local で LOCAL_ES_HOST=192.168.1.100 として設定
    local_es_host: str = Field(default="192.168.1.100", alias="LOCAL_ES_HOST")
    local_es_port: int = Field(default=9200, alias="LOCAL_ES_PORT")

    # === T-pot SSH Tunnel ===
    tpot_ssh_host: str = Field(default="209.97.173.122", alias="TPOT_SSH_HOST")
    tpot_ssh_port: int = Field(default=64295, alias="TPOT_SSH_PORT")
    tpot_ssh_user: str = Field(default="root", alias="TPOT_SSH_USER")
    tpot_ssh_key: str = Field(default="~/.ssh/digitalocean_key", alias="TPOT_SSH_KEY")
    tpot_es_host: str = Field(default="127.0.0.1", alias="TPOT_ES_HOST")
    tpot_es_port: int = Field(default=64298, alias="TPOT_ES_PORT")
    local_tpot_bind_port: int = Field(default=9201, alias="LOCAL_TPOT_BIND_PORT")

    # === External APIs ===
    virustotal_api_key: Optional[str] = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    otx_api_key: Optional[str] = Field(default=None, alias="OTX_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, alias="ABUSEIPDB_API_KEY")
    nvd_api_key: Optional[str] = Field(default=None, alias="NVD_API_KEY")
    github_api_token: Optional[str] = Field(default=None, alias="GITHUB_API_TOKEN")
    x_bearer_token: Optional[str] = Field(default=None, alias="X_BEARER_TOKEN")

    # === Scheduler ===
    scheduler_enabled: bool = Field(default=True, alias="SCHEDULER_ENABLED")
    refresh_interval_minutes: int = Field(default=5, alias="REFRESH_INTERVAL_MINUTES")

    # === Logging ===
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # === Environment & CORS ===
    env: str = Field(default="development", alias="ENV")
    frontend_url: Optional[str] = Field(default=None, alias="FRONTEND_URL")

    class Config:
        env_file = ".env.local"
        case_sensitive = False
        populate_by_name = True  # Allow both alias and field name

    # === Computed Properties ===
    @property
    def local_es_url(self) -> str:
        return f"http://{self.local_es_host}:{self.local_es_port}"

    @property
    def local_tpot_url(self) -> str:
        """URL for T-pot ES via SSH tunnel"""
        return f"http://localhost:{self.local_tpot_bind_port}"


# Global settings instance
settings = Settings()
