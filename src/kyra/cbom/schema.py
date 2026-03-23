"""CBOM schema — Pydantic models for Cryptography Bill of Materials."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class AlgorithmFamily(str, Enum):
    RSA = "RSA"
    ECC = "ECC"
    AES = "AES"
    DH = "DH"
    DSA = "DSA"
    SHA2 = "SHA-2"
    SHA3 = "SHA-3"
    MD5 = "MD5"
    SHA1 = "SHA-1"
    DES = "DES"
    TDES = "3DES"
    CHACHA20 = "ChaCha20"
    MLKEM = "ML-KEM"
    MLDSA = "ML-DSA"
    SLHDSA = "SLH-DSA"


class PQReadiness(str, Enum):
    QUANTUM_SAFE = "quantum-safe"
    HYBRID_READY = "hybrid-ready"
    MIGRATION_NEEDED = "migration-needed"
    CRITICAL = "critical"


class ExposureLevel(str, Enum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    STORAGE = "storage"
    TRANSIT = "transit"
    SIGNING = "signing"


class CBOMEntry(BaseModel):
    id: str
    component: str
    algorithm: str
    algorithm_family: AlgorithmFamily
    key_size: int | None = None
    usage_context: str
    exposure_level: ExposureLevel
    data_lifetime: str
    pq_readiness: PQReadiness
    location: str
    confidence: float = Field(ge=0.0, le=1.0)
    detected_by: str
    first_seen: datetime
    last_seen: datetime


class CBOMSummary(BaseModel):
    total_findings: int
    by_readiness: dict[str, int]
    by_algorithm_family: dict[str, int]
    by_exposure: dict[str, int]


class CBOMReport(BaseModel):
    version: str = "1.0.0"
    scan_id: str
    timestamp: datetime
    target: str
    entries: list[CBOMEntry]
    summary: CBOMSummary
