from pydantic import BaseModel


class AppConfig(BaseModel):
    app_name: str = "Threat Research MCP"
    default_transport: str = "stdio"
