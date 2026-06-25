"""
Schémas Pydantic partagés pour l'API.
"""

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

# Autorise : alphanumériques, points, tirets, underscores, deux-points, crochets,
# barres obliques (pour les CIDR/chemins), et @ (pour les domaines internationaux)
VALID_TARGET_PATTERN = re.compile(r'^[a-zA-Z0-9._\-:/\[\]@]+$')


# ---- Pagination ----
class Pagination(BaseModel):
    total: int
    offset: int
    limit: int


class PaginatedResponse(BaseModel):
    data: list[Any]
    pagination: Pagination


# ---- Target ----
class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, examples=["Serveur Web DMZ"])
    address: str = Field(..., min_length=1, max_length=255, examples=["192.168.1.10"])
    kind: str = Field(default="host", pattern=r"^(host|subnet|domain)$")
    tags: str | None = Field(None, examples=["web,dmz,production"])
    notes: str | None = None

    @field_validator("address", mode="before")
    @classmethod
    def validate_target_format(cls, v: str) -> str:
        if v and not VALID_TARGET_PATTERN.match(str(v)):
            raise ValueError(
                "Format cible invalide — seuls alphanumériques, points, tirets, "
                "deux-points autorisés"
            )
        return v


class TargetUpdate(BaseModel):
    name: str | None = None
    address: str | None = None
    kind: str | None = None
    tags: str | None = None
    notes: str | None = None
    alive: bool | None = None

    @field_validator("address", mode="before")
    @classmethod
    def validate_target_format(cls, v: str | None) -> str | None:
        if v and not VALID_TARGET_PATTERN.match(str(v)):
            raise ValueError(
                "Format cible invalide — seuls alphanumériques, points, tirets, "
                "deux-points autorisés"
            )
        return v


class TargetResponse(BaseModel):
    id: str
    name: str
    address: str
    kind: str
    tags: str | None = None
    notes: str | None = None
    alive: bool | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TargetListResponse(BaseModel):
    data: list[TargetResponse]
    pagination: Pagination


# ---- Scan ----
class ScanCreate(BaseModel):
    target_id: str = Field(..., examples=["uuid-de-la-cible"])
    scan_type: str = Field(default="tcp_connect", pattern=r"^(tcp_connect|tcp_syn|udp|service_detect|os_detect)$")
    ports: str | None = Field(None, examples=["1-1000,3306,8080"])


class ScanResponse(BaseModel):
    id: str
    target_id: str
    scan_type: str
    ports: str | None = None
    status: str
    progress: float
    result_summary: str | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    data: list[ScanResponse]
    pagination: Pagination


# ---- Task (Celery) ----
class TaskStatusResponse(BaseModel):
    """Statut d'une tâche Celery."""
    task_id: str
    state: str  # PENDING, PROGRESS, SUCCESS, FAILURE
    meta: dict | None = None
    result: dict | None = None


class ScanCreateResponse(BaseModel):
    """Réponse après création d'un scan avec tâche Celery."""
    task_id: str
    scan_id: str
    status: str = "PENDING"
    message: str = "Scan lancé en arrière-plan"


class TaskProgressEvent(BaseModel):
    """Événement SSE pour la progression d'un scan."""
    event: str = "progress"
    data: dict


# ---- Service ----
class ServiceResponse(BaseModel):
    id: str
    target_id: str
    scan_id: str | None = None
    port: int = Field(..., ge=1, le=65535)
    protocol: str
    state: str
    service_name: str | None = None
    banner: str | None = None
    version: str | None = None
    discovered_at: datetime

    model_config = {"from_attributes": True}
