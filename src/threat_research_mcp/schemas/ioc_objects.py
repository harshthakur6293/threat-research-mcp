"""Structured IOC payloads (extracted or observed in intel)."""

from __future__ import annotations

import uuid
from typing import Literal, Union

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated

from pydantic import BaseModel, ConfigDict, Field


class IocBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    context: str = ""
    source_snippet: str = ""


class IocIpv4(IocBase):
    kind: Literal["ipv4"] = "ipv4"
    value: str


class IocIpv6(IocBase):
    kind: Literal["ipv6"] = "ipv6"
    value: str


class IocDomain(IocBase):
    kind: Literal["domain"] = "domain"
    value: str


class IocUrl(IocBase):
    kind: Literal["url"] = "url"
    value: str


class IocEmail(IocBase):
    kind: Literal["email"] = "email"
    value: str


class IocHash(IocBase):
    kind: Literal["hash"] = "hash"
    algorithm: Literal["md5", "sha1", "sha256", "sha512", "other"] = "sha256"
    value: str


class IocFilePath(IocBase):
    kind: Literal["file_path"] = "file_path"
    value: str


class IocRegistryKey(IocBase):
    kind: Literal["registry_key"] = "registry_key"
    value: str


class IocMutex(IocBase):
    kind: Literal["mutex"] = "mutex"
    value: str


class IocOther(IocBase):
    kind: Literal["other"] = "other"
    label: str = "custom"
    value: str


IocObject = Annotated[
    Union[
        IocIpv4,
        IocIpv6,
        IocDomain,
        IocUrl,
        IocEmail,
        IocHash,
        IocFilePath,
        IocRegistryKey,
        IocMutex,
        IocOther,
    ],
    Field(discriminator="kind"),
]
