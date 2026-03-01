"""
Modèle de log normalisé conforme ANSSI.

Chaque entrée de log collectée est normalisée vers ce format
avant d'entrer dans le pipeline LangGraph.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class LogSource(str, Enum):
    NGINX = "nginx"
    APACHE = "apache"
    SSH = "ssh"
    AUDITD = "auditd"
    KERNEL = "kernel"
    APPLICATION = "application"
    FIREWALL = "firewall"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogEntry(BaseModel):
    """Entrée de log normalisée (format interne pipeline)."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    source: LogSource = LogSource.UNKNOWN
    host: str
    raw_message: str
    normalized_message: str = ""
    severity: SeverityLevel = SeverityLevel.INFO
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Champs ANSSI : traçabilité
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    hmac_signature: str = ""  # Calculé lors de l'archivage
    integrity_verified: bool = False

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, str):
            return datetime.fromisoformat(v)
        return v

    @property
    def is_high_severity(self) -> bool:
        return self.severity in (SeverityLevel.ERROR, SeverityLevel.CRITICAL)

    def to_audit_dict(self) -> dict[str, Any]:
        """Représentation pour la table d'audit (sans données sensibles)."""
        return {
            "log_id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source.value,
            "host": self.host,
            "severity": self.severity.value,
            "tags": self.tags,
            "hmac_signature": self.hmac_signature,
            "integrity_verified": self.integrity_verified,
        }
