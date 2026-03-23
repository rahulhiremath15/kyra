# KYRA — Post-Quantum Cryptography Readiness Platform

## MVP Architecture Document

**Version:** 0.1.0
**Date:** 2026-03-14
**Author:** Security Infrastructure Engineering

---

## 1. MVP PRODUCT DEFINITION

### What KYRA v1 Does

KYRA scans codebases and infrastructure configurations, finds every place cryptography is used, catalogs it into a Cryptography Bill of Materials (CBOM), and tells you which parts are vulnerable to future quantum computers.

**Simple explanation:** Imagine someone going through your entire codebase with a highlighter, marking every lock (encryption) and key. Then they tell you which locks a quantum computer could pick, and how urgent it is to replace them. That's KYRA.

### Target User

- **Primary:** Security engineers and DevSecOps leads at companies handling sensitive data (financial, healthcare, government contractors, SaaS)
- **Secondary:** CTOs and engineering managers who need to report on PQC readiness to compliance teams
- **Tertiary:** Individual developers building security-sensitive applications

### Core Use Cases

1. **Crypto Discovery** — "I don't know where we use RSA/ECC/AES across our codebase"
2. **CBOM Generation** — "I need a machine-readable inventory of all cryptographic assets for compliance"
3. **HNDL Risk Assessment** — "Which data is most vulnerable to harvest-now-decrypt-later attacks?"
4. **Upgrade Prioritization** — "Where should I start migrating to post-quantum algorithms?"

### Why Developers Would Use It Immediately

- **NIST finalized PQC standards in 2024.** FIPS 203, 204, 205 are published. Compliance timelines are active.
- **NSA CNSA 2.0** mandates PQC adoption for national security systems by 2030–2035.
- **No good open-source tool exists** that combines crypto discovery + CBOM + HNDL risk scoring in one workflow.
- **Runs locally.** No SaaS dependency. No code leaves your machine.
- **Works in CI.** One command in your pipeline. Fail builds if HNDL risk exceeds threshold.

---

## 2. MVP SYSTEM ARCHITECTURE

### Design Philosophy

The architecture follows principles from the `everything-claude-code` repository:

- **Pipeline decomposition** (DAG Orchestration pattern) — each stage is independent and testable
- **Read-only scanning** (Taint Mode / Safe I/O) — scanner never modifies source
- **Verification loops** (Checkpoint Evals) — each pipeline stage validates its output before passing downstream
- **Layered rules** (Rules Architecture) — detection rules are data, not code. Easy to extend without rewriting logic
- **Content hash caching** — skip unchanged files on re-scan

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                      CLI (kyra)                         │
│   kyra scan · kyra cbom · kyra risk · kyra dashboard    │
└────────┬──────────┬───────────┬──────────┬──────────────┘
         │          │           │          │
         ▼          ▼           ▼          ▼
┌──────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐
│ Scanner  │─▶│   CBOM   │─▶│  Risk  │─▶│ Dashboard │
│          │  │Generator │  │ Engine │  │   (Web)   │
└──────────┘  └──────────┘  └────────┘  └───────────┘
     │              │            │            │
     ▼              ▼            ▼            ▼
┌─────────────────────────────────────────────────────────┐
│                   Local Data Store                       │
│              (SQLite + JSON exports)                     │
└─────────────────────────────────────────────────────────┘
```

### Component Summary

| Component | What It Does | Why It Exists | Interactions |
|-----------|-------------|---------------|--------------|
| **Scanner** | Finds cryptographic usage in code, configs, and certificates | Discovery is the foundation — you can't secure what you don't know about | Outputs raw findings → CBOM Generator |
| **CBOM Generator** | Structures findings into a standardized Cryptography Bill of Materials | Compliance teams need machine-readable inventories; downstream analysis needs structured data | Consumes scanner output → produces CBOM → feeds Risk Engine |
| **Risk Engine** | Calculates HNDL risk scores per finding and overall | Prioritization — not all crypto is equally urgent to migrate | Consumes CBOM → produces scored results → feeds Dashboard + CLI |
| **CLI** | Command-line interface for all operations | Developer UX — must work in terminals and CI pipelines | Orchestrates all components |
| **Dashboard** | Web UI for visualization | Executives and security leads need visual summaries for reporting | Reads scored CBOM from API |
| **Data Store** | SQLite database + JSON export | Persistence across scans, diff tracking, no infrastructure dependencies | All components read/write |

### How `everything-claude-code` Patterns Apply

| Pattern | Application in KYRA |
|---------|-------------------|
| **DAG Orchestration** | Scanner → CBOM → Risk is a strict pipeline. Each stage is independently testable and can be run in isolation. |
| **Verification Loops** | Each pipeline stage validates its output schema before passing data downstream. Scanner validates findings against known patterns. CBOM validates against schema. Risk engine validates scores are within bounds. |
| **Content Hash Caching** | Scanner computes SHA-256 of each file. On re-scan, unchanged files are skipped. Stored in SQLite. |
| **Rules Architecture** | Detection patterns are YAML rule files, not hardcoded. Language-specific rules live in `scanner/rules/{language}/`. Common rules live in `scanner/rules/common/`. |
| **Security Reviewer** | Risk engine acts as an automated security reviewer — flagging weak algorithms and generating upgrade recommendations. |
| **Session State Tracking** | Scan results are persisted in SQLite with timestamps. `kyra diff` can compare scans over time. |
| **Research-First Workflow** | Scanner runs discovery before analysis. CBOM structures before scoring. No stage skips ahead. |
| **TDD Workflow** | Every component has a test suite. Scanner rules ship with positive and negative test cases. |
| **Quality Gates** | CLI supports `--fail-on-risk=high` for CI integration. Pipeline fails if HNDL risk exceeds threshold. |

---

## 3. REPOSITORY STRUCTURE

```
kyra/
├── pyproject.toml              # Project metadata, dependencies (single source of truth)
├── README.md                   # Project overview
├── ARCHITECTURE.md             # This document
├── LICENSE
│
├── src/
│   └── kyra/
│       ├── __init__.py
│       ├── __main__.py         # Entry point: python -m kyra
│       │
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── main.py         # Click/Typer CLI app definition
│       │   ├── scan.py         # kyra scan commands
│       │   ├── cbom.py         # kyra cbom commands
│       │   ├── risk.py         # kyra risk commands
│       │   └── dashboard.py    # kyra dashboard command (launches web UI)
│       │
│       ├── scanner/
│       │   ├── __init__.py
│       │   ├── engine.py       # Core scanning orchestrator
│       │   ├── file_walker.py  # File discovery with .gitignore respect
│       │   ├── cache.py        # SHA-256 content hash caching
│       │   ├── detectors/
│       │   │   ├── __init__.py
│       │   │   ├── base.py     # Abstract detector interface
│       │   │   ├── regex.py    # Regex-based pattern matcher
│       │   │   ├── ast_py.py   # Python AST parser (import detection)
│       │   │   ├── tls.py      # TLS/SSL config parser
│       │   │   └── cert.py     # X.509 certificate analyzer
│       │   └── rules/
│       │       ├── common/
│       │       │   ├── algorithms.yaml    # Algorithm pattern definitions
│       │       │   └── key_sizes.yaml     # Key size patterns
│       │       ├── python/
│       │       │   └── crypto_imports.yaml
│       │       ├── java/
│       │       │   └── crypto_imports.yaml
│       │       ├── javascript/
│       │       │   └── crypto_imports.yaml
│       │       └── config/
│       │           ├── tls.yaml
│       │           ├── nginx.yaml
│       │           └── openssl.yaml
│       │
│       ├── cbom/
│       │   ├── __init__.py
│       │   ├── generator.py    # Transforms scan findings → CBOM entries
│       │   ├── schema.py       # Pydantic models for CBOM data
│       │   └── export.py       # JSON/CSV export
│       │
│       ├── risk/
│       │   ├── __init__.py
│       │   ├── engine.py       # HNDL risk calculation
│       │   ├── scoring.py      # Score formulas and weights
│       │   ├── factors.py      # Risk factor definitions
│       │   └── recommendations.py  # Upgrade path suggestions
│       │
│       ├── api/
│       │   ├── __init__.py
│       │   ├── app.py          # FastAPI application
│       │   └── routes.py       # API endpoints for dashboard
│       │
│       ├── dashboard/
│       │   ├── static/         # Built React app (served by FastAPI)
│       │   └── README.md
│       │
│       └── db/
│           ├── __init__.py
│           ├── store.py        # SQLite operations
│           └── models.py       # Database models
│
├── dashboard-ui/               # React/Next.js source (builds into src/kyra/dashboard/static/)
│   ├── package.json
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── CryptoInventory.tsx
│   │   │   ├── RiskOverview.tsx
│   │   │   ├── FindingDetail.tsx
│   │   │   └── UpgradeRecommendations.tsx
│   │   └── api/
│   │       └── client.ts
│   └── public/
│
├── tests/
│   ├── conftest.py
│   ├── test_scanner/
│   │   ├── test_engine.py
│   │   ├── test_regex.py
│   │   ├── test_ast.py
│   │   ├── test_tls.py
│   │   └── test_cert.py
│   ├── test_cbom/
│   │   ├── test_generator.py
│   │   └── test_schema.py
│   ├── test_risk/
│   │   ├── test_engine.py
│   │   └── test_scoring.py
│   └── fixtures/
│       ├── sample_code/        # Test repos with known crypto usage
│       ├── sample_certs/       # Test certificates
│       └── sample_configs/     # Test TLS/nginx configs
│
└── docs/
    └── rules.md                # How to write custom detection rules
```

### Folder Explanation

| Folder | Contents |
|--------|----------|
| `src/kyra/cli/` | Typer-based CLI. One file per command group. Thin layer — delegates to scanner/cbom/risk. |
| `src/kyra/scanner/` | All detection logic. `engine.py` orchestrates detectors. `detectors/` contains pluggable detection strategies. `rules/` contains YAML pattern definitions — data, not code. |
| `src/kyra/cbom/` | Transforms raw scanner findings into structured CBOM format. Pydantic schemas ensure data integrity. |
| `src/kyra/risk/` | HNDL risk scoring. Consumes CBOM, produces scored output with upgrade recommendations. |
| `src/kyra/api/` | FastAPI server. Minimal — serves CBOM data and risk scores to the dashboard. |
| `src/kyra/dashboard/` | Built static assets from the React UI. Served directly by FastAPI. No separate frontend server needed. |
| `src/kyra/db/` | SQLite persistence. Stores scan history, cached hashes, CBOM snapshots. |
| `dashboard-ui/` | React source code. Builds to `src/kyra/dashboard/static/`. Separate from Python package. |
| `tests/` | Pytest test suite. Mirrors `src/` structure. Fixtures include sample code with known crypto patterns for deterministic testing. |

---

## 4. CBOM DATA MODEL

### Schema (Pydantic)

```python
from pydantic import BaseModel
from enum import Enum
from typing import Optional
from datetime import datetime

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
    MLKEM = "ML-KEM"         # Post-quantum
    MLDSA = "ML-DSA"         # Post-quantum
    SLHDSA = "SLH-DSA"       # Post-quantum

class PQReadiness(str, Enum):
    QUANTUM_SAFE = "quantum-safe"       # Already PQC or symmetric ≥256
    HYBRID_READY = "hybrid-ready"       # Can add PQC alongside classical
    MIGRATION_NEEDED = "migration-needed"  # Must replace
    CRITICAL = "critical"                # Broken or near-broken (MD5, SHA-1, DES)

class ExposureLevel(str, Enum):
    EXTERNAL = "external"    # Internet-facing (TLS, public APIs)
    INTERNAL = "internal"    # Internal services
    STORAGE = "storage"      # Data at rest
    TRANSIT = "transit"      # Data in motion (non-public)
    SIGNING = "signing"      # Code/document signing

class CBOMEntry(BaseModel):
    id: str                              # Unique finding ID
    component: str                       # e.g., "backend/auth/jwt.py"
    algorithm: str                       # e.g., "RSA-2048"
    algorithm_family: AlgorithmFamily
    key_size: Optional[int]              # In bits, if applicable
    usage_context: str                   # e.g., "JWT token signing"
    exposure_level: ExposureLevel
    data_lifetime: str                   # e.g., "7y" (7 years), "90d", "session"
    pq_readiness: PQReadiness
    location: str                        # File path + line number
    confidence: float                    # 0.0–1.0 detection confidence
    detected_by: str                     # Which detector found it
    first_seen: datetime
    last_seen: datetime

class CBOMReport(BaseModel):
    version: str = "1.0.0"
    scan_id: str
    timestamp: datetime
    target: str                          # Scanned directory
    entries: list[CBOMEntry]
    summary: "CBOMSummary"

class CBOMSummary(BaseModel):
    total_findings: int
    by_readiness: dict[PQReadiness, int]
    by_algorithm_family: dict[str, int]
    by_exposure: dict[ExposureLevel, int]
```

### Example JSON Output

```json
{
  "version": "1.0.0",
  "scan_id": "scan-20260314-a1b2c3",
  "timestamp": "2026-03-14T10:30:00Z",
  "target": "/home/dev/myapp",
  "summary": {
    "total_findings": 4,
    "by_readiness": {
      "critical": 1,
      "migration-needed": 2,
      "quantum-safe": 1
    },
    "by_algorithm_family": {
      "RSA": 1,
      "ECC": 1,
      "SHA-1": 1,
      "AES": 1
    },
    "by_exposure": {
      "external": 2,
      "storage": 1,
      "signing": 1
    }
  },
  "entries": [
    {
      "id": "finding-001",
      "component": "backend/auth/jwt.py",
      "algorithm": "RSA-2048",
      "algorithm_family": "RSA",
      "key_size": 2048,
      "usage_context": "JWT token signing for user authentication",
      "exposure_level": "external",
      "data_lifetime": "30d",
      "pq_readiness": "migration-needed",
      "location": "backend/auth/jwt.py:42",
      "confidence": 0.95,
      "detected_by": "ast-python",
      "first_seen": "2026-03-14T10:30:00Z",
      "last_seen": "2026-03-14T10:30:00Z"
    },
    {
      "id": "finding-002",
      "component": "nginx/nginx.conf",
      "algorithm": "ECDHE-RSA-AES128-GCM-SHA256",
      "algorithm_family": "ECC",
      "key_size": 256,
      "usage_context": "TLS cipher suite for HTTPS termination",
      "exposure_level": "external",
      "data_lifetime": "session",
      "pq_readiness": "migration-needed",
      "location": "nginx/nginx.conf:18",
      "confidence": 0.99,
      "detected_by": "config-parser",
      "first_seen": "2026-03-14T10:30:00Z",
      "last_seen": "2026-03-14T10:30:00Z"
    },
    {
      "id": "finding-003",
      "component": "backend/utils/hash.py",
      "algorithm": "SHA-1",
      "algorithm_family": "SHA-1",
      "key_size": null,
      "usage_context": "File integrity checking in upload pipeline",
      "exposure_level": "signing",
      "data_lifetime": "7y",
      "pq_readiness": "critical",
      "location": "backend/utils/hash.py:15",
      "confidence": 0.90,
      "detected_by": "regex",
      "first_seen": "2026-03-14T10:30:00Z",
      "last_seen": "2026-03-14T10:30:00Z"
    },
    {
      "id": "finding-004",
      "component": "backend/storage/encrypt.py",
      "algorithm": "AES-256-GCM",
      "algorithm_family": "AES",
      "key_size": 256,
      "usage_context": "Encryption of user PII at rest",
      "exposure_level": "storage",
      "data_lifetime": "5y",
      "pq_readiness": "quantum-safe",
      "location": "backend/storage/encrypt.py:28",
      "confidence": 0.97,
      "detected_by": "ast-python",
      "first_seen": "2026-03-14T10:30:00Z",
      "last_seen": "2026-03-14T10:30:00Z"
    }
  ]
}
```

### Field Explanations

| Field | Simple Explanation |
|-------|-------------------|
| `component` | The file or service where crypto was found. Like a street address. |
| `algorithm` | The specific crypto algorithm and parameters. Like the brand and model of a lock. |
| `algorithm_family` | The general category (RSA, ECC, AES...). Like saying "deadbolt" vs "padlock". |
| `key_size` | How big the key is in bits. Bigger is generally harder to break. A quantum computer breaks RSA-2048 regardless of size, but AES-256 remains safe. |
| `usage_context` | What this crypto is actually protecting. "JWT signing" or "TLS for API" — tells you what breaks if this algorithm is compromised. |
| `exposure_level` | How accessible this is to an attacker. Internet-facing services are higher risk than internal storage. |
| `data_lifetime` | How long this data needs to stay secret. Medical records (decades) matter more than session tokens (hours) for HNDL risk. |
| `pq_readiness` | The verdict: is this already safe from quantum computers, or does it need to be replaced? |
| `confidence` | How certain we are about this detection. AST parsing is more confident than regex matching. |
| `detected_by` | Which detection method found this. Useful for understanding false positive likelihood. |

---

## 5. SCANNER DESIGN

### Detection Strategy

The scanner uses three detection methods, ordered from cheapest to most accurate:

#### 5.1 Regex Pattern Detection

**What:** Pattern matching against known cryptographic function names, constants, and configuration keywords.

**Targets:**
- Function calls: `RSA.generate(2048)`, `ECDSA.sign()`, `hashlib.sha1()`
- Constants: `ssl.PROTOCOL_TLSv1_2`, `Cipher.AES`, `KeySize = 2048`
- Config values: `ssl_ciphers`, `SSLProtocol`, `tls_version`

**Rule format (YAML):**
```yaml
# scanner/rules/common/algorithms.yaml
- id: rsa-key-generation
  pattern: "RSA\\.generate\\s*\\(\\s*(\\d+)"
  algorithm_family: RSA
  capture_groups:
    key_size: 1
  confidence: 0.85
  description: "RSA key generation"

- id: sha1-usage
  pattern: "sha1|SHA1|SHA-1|hashlib\\.sha1"
  algorithm_family: SHA-1
  confidence: 0.70
  description: "SHA-1 hash usage"
```

**Limitations:**
- Cannot understand context (variable aliasing, wrappers)
- False positives on comments, strings, dead code
- Cannot determine key sizes from variables

**Applied pattern (Regex vs. LLM Decision Framework):** For MVP, regex handles 80%+ of detections. LLM-based detection is a future enhancement, not MVP scope.

#### 5.2 AST Parsing (Python initial scope)

**What:** Parses Python source into Abstract Syntax Trees to find cryptographic library imports and their usage.

**Targets:**
- `from cryptography.hazmat.primitives.asymmetric import rsa`
- `from Crypto.Cipher import AES`
- `import hashlib`
- `ssl.create_default_context()`

**How it works:**
1. Parse file with `ast.parse()`
2. Walk the tree for `Import` and `ImportFrom` nodes
3. Match against known cryptographic module paths
4. Follow usage of imported names to find parameters (key sizes, algorithms)
5. Extract line numbers and context

**Advantages over regex:**
- Understands Python structure — avoids false positives in strings/comments
- Can resolve `from X import Y as Z` aliasing
- Can extract function call arguments for key sizes

**Limitations:**
- Python-only in MVP (Java/JS AST support is a post-MVP item)
- Cannot resolve runtime values (`key_size = config.get("key_size")`)

#### 5.3 Config and Certificate Parsing

**TLS configurations:**
- Parse nginx `ssl_ciphers` and `ssl_protocols` directives
- Parse Apache `SSLProtocol` and `SSLCipherSuite`
- Parse application-level TLS settings (Python `ssl` module, Node.js `tls`)

**X.509 Certificates:**
- Parse `.pem`, `.crt`, `.cer` files using Python `cryptography` library
- Extract: signature algorithm, public key type, key size, validity dates
- **Safety:** Only reads public certificate data. Never touches private key files.

```python
# Simplified certificate scanning logic
from cryptography import x509

def analyze_cert(cert_path: str) -> dict:
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    pub_key = cert.public_key()
    return {
        "algorithm": cert.signature_algorithm_oid._name,
        "key_type": type(pub_key).__name__,
        "key_size": pub_key.key_size,
        "not_after": cert.not_valid_after_utc,
    }
```

### Scanner Orchestration

```
File Walker (respects .gitignore, .kyraignore)
    │
    ├── Content Hash Cache (SHA-256) ─── skip unchanged files
    │
    ├── File type router:
    │   ├── .py           → AST detector + regex detector
    │   ├── .java/.js/.go → regex detector (AST in future)
    │   ├── .conf/.yaml   → config parser
    │   ├── .pem/.crt     → certificate analyzer
    │   └── everything    → regex detector (catch-all)
    │
    └── Finding deduplicator + confidence merger
```

### Safety Considerations

- **Read-only.** Scanner opens files with `O_RDONLY`. No writes, ever.
- **Private key exclusion.** Files matching `*.key`, `*.pem` (with private key headers), `*private*` are scanned for metadata only — content is never stored or transmitted.
- **Path sanitization.** Scanner rejects symlinks pointing outside the scan root to prevent directory traversal.
- **Resource limits.** Max file size (10MB default), max scan depth, timeout per file.
- **No network.** Scanner makes zero network calls. Everything is local.

---

## 6. RISK ENGINE

### HNDL Risk Model

**The problem HNDL measures:** An attacker can record encrypted traffic today and decrypt it later when quantum computers exist. The risk depends on three things:

1. **How weak is the algorithm against quantum computers?**
2. **How long does the data need to stay secret?**
3. **How exposed is the data to interception?**

### Risk Formula

```
HNDL_RISK = algorithm_risk × lifetime_factor × exposure_factor
```

Each factor is scored 0.0 to 1.0. The final score maps to a risk level:

| Score Range | Risk Level | Meaning |
|-------------|-----------|---------|
| 0.0 – 0.2 | LOW | Quantum-safe or minimal exposure |
| 0.2 – 0.5 | MEDIUM | Some migration needed, not urgent |
| 0.5 – 0.8 | HIGH | Should be migrated within 1–2 years |
| 0.8 – 1.0 | CRITICAL | Actively vulnerable. Migrate immediately. |

### Factor Definitions

#### Algorithm Risk (`algorithm_risk`)

Based on NIST and NSA CNSA 2.0 guidance:

| Algorithm | Score | Reasoning |
|-----------|-------|-----------|
| MD5, SHA-1 (signing) | 1.0 | Already broken classically |
| DES, 3DES | 1.0 | Deprecated |
| RSA-1024 | 1.0 | Broken classically + quantum |
| RSA-2048 | 0.9 | Safe classically, broken by CRQC |
| RSA-4096 | 0.85 | Same quantum vulnerability, larger margin |
| ECDSA/ECDH (P-256) | 0.9 | Safe classically, broken by CRQC |
| ECDSA/ECDH (P-384) | 0.85 | Same |
| DH-2048 | 0.9 | Same as RSA |
| AES-128 | 0.3 | Grover's reduces to 64-bit — debatable |
| AES-256 | 0.05 | Grover's reduces to 128-bit — still safe |
| ChaCha20-Poly1305 | 0.1 | 256-bit symmetric — safe |
| SHA-256 (hashing) | 0.1 | Collision resistance halved but still adequate |
| SHA-384/SHA-512 | 0.05 | Safe |
| ML-KEM | 0.02 | NIST PQC standard |
| ML-DSA | 0.02 | NIST PQC standard |
| SLH-DSA | 0.02 | NIST PQC standard |

#### Data Lifetime Factor (`lifetime_factor`)

How long does intercepted data remain valuable?

| Lifetime | Score | Examples |
|----------|-------|---------|
| Session/ephemeral | 0.1 | WebSocket sessions, OTPs |
| Days (< 30d) | 0.2 | Short-lived tokens, temporary URLs |
| Months (30d–1y) | 0.4 | API keys, refresh tokens |
| Years (1–5y) | 0.7 | User PII, financial records |
| Decades (5y+) | 0.9 | Medical records, classified data, trade secrets |
| Permanent | 1.0 | Signing keys, long-term identity credentials |

#### Exposure Factor (`exposure_factor`)

How accessible is this data to an attacker capable of recording traffic?

| Exposure | Score | Examples |
|----------|-------|---------|
| Air-gapped/offline | 0.1 | HSM-stored keys, offline backups |
| Internal network only | 0.3 | Service-to-service mTLS, internal APIs |
| VPN-accessible | 0.5 | Remote access, hybrid cloud links |
| Internet-facing | 0.9 | Public TLS endpoints, public APIs |
| Already public | 0.1 | Public certificates (nothing to steal) |

### Example Calculations

**Case 1: JWT signing with RSA-2048 on a public API**
```
algorithm_risk = 0.9   (RSA-2048, quantum-vulnerable)
lifetime_factor = 0.2   (tokens expire in 30 days)
exposure_factor = 0.9   (internet-facing)

HNDL_RISK = 0.9 × 0.2 × 0.9 = 0.162 → LOW
```
Why low? Even though RSA-2048 is quantum-vulnerable, the tokens are short-lived. By the time a quantum computer exists, these tokens are worthless.

**Case 2: RSA-2048 encrypting medical records at rest**
```
algorithm_risk = 0.9   (RSA-2048, quantum-vulnerable)
lifetime_factor = 0.9   (medical records: decades)
exposure_factor = 0.3   (internal storage network)

HNDL_RISK = 0.9 × 0.9 × 0.3 = 0.243 → MEDIUM
```
Lower exposure compensates somewhat, but data lifetime makes this a real concern.

**Case 3: ECDHE on a public HTTPS endpoint protecting financial transactions**
```
algorithm_risk = 0.9   (ECDH P-256, quantum-vulnerable)
lifetime_factor = 0.7   (financial records: years of relevance)
exposure_factor = 0.9   (internet-facing)

HNDL_RISK = 0.9 × 0.7 × 0.9 = 0.567 → HIGH
```
This is a real HNDL risk. Adversaries can record today, decrypt after CRQC.

**Case 4: AES-256-GCM for data at rest**
```
algorithm_risk = 0.05  (quantum-safe)
lifetime_factor = 0.7   (years)
exposure_factor = 0.3   (internal)

HNDL_RISK = 0.05 × 0.7 × 0.3 = 0.0105 → LOW
```
AES-256 is quantum-safe. No action needed.

### Upgrade Recommendations

The risk engine maps each finding to a migration recommendation:

| Current Algorithm | Recommended Upgrade | Standard |
|-------------------|-------------------|----------|
| RSA (any size, key exchange) | ML-KEM-768 or ML-KEM-1024 | FIPS 203 |
| ECDH (key exchange) | ML-KEM-768 or X25519+ML-KEM-768 hybrid | FIPS 203 |
| RSA (signing) | ML-DSA-65 or ML-DSA-87 | FIPS 204 |
| ECDSA (signing) | ML-DSA-65 or SLH-DSA-SHA2-128s | FIPS 204/205 |
| DH (key exchange) | ML-KEM-768 | FIPS 203 |
| SHA-1 | SHA-256 (immediate, pre-quantum) | — |
| MD5 | SHA-256 (immediate, pre-quantum) | — |
| AES-128 | AES-256 (precautionary) | — |

---

## 7. CLI EXPERIENCE

### Installation

```bash
pip install kyra
# or
pipx install kyra
```

### Core Commands

#### `kyra scan`

```bash
$ kyra scan .

 KYRA Scanner v0.1.0
 Scanning: /home/dev/myapp

 Files scanned:  342
 Files skipped:  128 (cached, unchanged)
 Time:           2.3s

 Findings:
 ┌────────────────────────────────────┬─────────────┬──────────┬───────────────────┐
 │ Location                           │ Algorithm   │ Key Size │ PQ Readiness      │
 ├────────────────────────────────────┼─────────────┼──────────┼───────────────────┤
 │ backend/auth/jwt.py:42             │ RSA-2048    │ 2048     │ migration-needed  │
 │ backend/utils/hash.py:15           │ SHA-1       │ —        │ critical          │
 │ nginx/nginx.conf:18                │ ECDHE-RSA   │ 256      │ migration-needed  │
 │ backend/storage/encrypt.py:28      │ AES-256-GCM │ 256      │ quantum-safe      │
 └────────────────────────────────────┴─────────────┴──────────┴───────────────────┘

 Summary: 2 migration-needed · 1 critical · 1 quantum-safe
```

#### `kyra cbom generate`

```bash
$ kyra cbom generate --format json --output cbom.json

 CBOM generated: cbom.json
 4 entries, schema version 1.0.0

$ kyra cbom generate --format csv --output cbom.csv

 CBOM generated: cbom.csv
```

#### `kyra risk analyze`

```bash
$ kyra risk analyze

 KYRA HNDL Risk Analysis
 ─────────────────────────────────────────────────────

 Overall HNDL Risk: MEDIUM (0.38)

 ┌────────────────────────────────────┬────────┬───────────────┐
 │ Finding                            │ Score  │ Risk Level    │
 ├────────────────────────────────────┼────────┼───────────────┤
 │ RSA-2048 @ backend/auth/jwt.py:42  │ 0.162  │ LOW           │
 │ SHA-1 @ backend/utils/hash.py:15   │ 0.630  │ HIGH          │
 │ ECDHE @ nginx/nginx.conf:18        │ 0.567  │ HIGH          │
 │ AES-256 @ backend/storage/enc..    │ 0.011  │ LOW           │
 └────────────────────────────────────┴────────┴───────────────┘

 Recommendations:
  → Replace SHA-1 with SHA-256 immediately (classically broken)
  → Plan ECDHE → ML-KEM hybrid migration within 12 months
  → RSA-2048 JWT signing: low urgency (short-lived tokens)
  → AES-256-GCM: no action needed (quantum-safe)
```

#### `kyra risk analyze --fail-on-risk=high` (CI mode)

```bash
$ kyra risk analyze --fail-on-risk=high
 ...
 2 findings at HIGH or above.
 EXIT CODE: 1
```

This fails the CI pipeline if any finding meets or exceeds the threshold.

#### `kyra dashboard`

```bash
$ kyra dashboard

 Starting KYRA dashboard...
 Dashboard available at: http://localhost:8390
 Press Ctrl+C to stop.
```

---

## 8. DASHBOARD DESIGN

### Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Backend | FastAPI (Python) | Same language as core engine. One dependency chain. Async. |
| Frontend | React + Vite + Tailwind CSS | Simple SPA. Builds to static files served by FastAPI. No Node.js runtime needed in production. |
| Charts | Recharts or Chart.js | Lightweight. No D3 overhead for MVP. |
| State | React Query (TanStack Query) | Handles API caching—no Redux needed for MVP. |

### Pages

#### 8.1 Overview Dashboard

```
┌─────────────────────────────────────────────────────────┐
│  KYRA — Cryptographic Risk Dashboard                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │  Total       │  │  HNDL Risk  │  │  Action      │    │
│  │  Findings: 4 │  │  MEDIUM     │  │  Required: 3 │    │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                         │
│  PQ Readiness Breakdown         Risk Distribution       │
│  ┌─────────────────────┐       ┌───────────────────┐    │
│  │ ██████░░ quantum-safe│       │ ██░░░░░░░░ LOW    │   │
│  │ ████████████ migrate │       │ ████████░░ HIGH   │   │
│  │ ████░░░░░░ critical  │       │                   │   │
│  └─────────────────────┘       └───────────────────┘    │
│                                                         │
│  Recent Findings                                        │
│  ┌─────────────────────────────────────────────────┐    │
│  │ File          │ Algorithm │ Risk  │ Action       │   │
│  │ auth/jwt.py   │ RSA-2048  │ LOW   │ Plan migrate │   │
│  │ utils/hash.py │ SHA-1     │ HIGH  │ Replace now  │   │
│  │ nginx.conf    │ ECDHE     │ HIGH  │ Add PQ hybrid│   │
│  │ encrypt.py    │ AES-256   │ LOW   │ None         │   │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### 8.2 Finding Detail View

Click any finding to see:
- Full file path and line number
- Code snippet (surrounding 5 lines)
- Risk score breakdown (algorithm × lifetime × exposure)
- Recommended migration path with NIST standard references

#### 8.3 Upgrade Recommendations View

Grouped by urgency:
- **Immediate** — SHA-1, MD5, DES (classically broken)
- **Within 12 months** — RSA/ECC on internet-facing, long-lifetime data
- **Plan for 2027–2030** — Internal RSA/ECC with shorter data lifetimes
- **No action** — AES-256, quantum-safe algorithms

### API Endpoints

```
GET  /api/v1/scan/latest          — Latest scan results
GET  /api/v1/cbom                 — Full CBOM
GET  /api/v1/cbom/{id}            — Single CBOM entry
GET  /api/v1/risk/summary         — Overall risk summary
GET  /api/v1/risk/findings        — All findings with scores
GET  /api/v1/risk/findings/{id}   — Single finding detail
GET  /api/v1/recommendations      — Upgrade recommendations
```

All endpoints return JSON. The API is read-only — no mutations. Dashboard is purely a viewer.

---

## 9. SAFETY AND PRIVACY

### Core Safety Guarantees

| Guarantee | Implementation |
|-----------|---------------|
| **Scanner is read-only** | Files opened with read-only flags. No write, rename, or delete operations exist in scanner code. Enforced by code review and tests that assert no write syscalls. |
| **Private keys are never collected** | Files with private key PEM headers (`-----BEGIN.*PRIVATE KEY-----`) are detected but their content is never stored. Only metadata (file path, key type, key size) enters the CBOM. |
| **All analysis runs locally** | Zero network calls in scanner, CBOM generator, or risk engine. No telemetry, no phone-home, no cloud dependency. Verified by integration tests that run with network disabled. |
| **No sensitive data leaves the environment** | CBOM contains file paths and algorithm identifiers — never actual keys, passwords, or encrypted data. Dashboard serves on `localhost` only by default. |
| **Symlink safety** | Scanner resolves symlinks and rejects any that point outside the scan root. Prevents directory traversal attacks. |
| **Resource limits** | Max file size (10MB), max directory depth (50), per-file timeout (5s). Prevents the scanner from hanging on adversarial inputs. |

### Privacy Architecture

```
┌──────────────────────────────────────────┐
│           User's Machine                  │
│                                           │
│  ┌─────────┐  ┌──────┐  ┌────────────┐  │
│  │ Scanner ├──▶ CBOM ├──▶ Risk Engine │  │
│  └─────────┘  └──────┘  └──────┬─────┘  │
│                                 │        │
│                          ┌──────▼─────┐  │
│                          │ Dashboard   │  │  ← localhost:8390
│                          │ (local)     │  │     no external access
│                          └────────────┘  │
│                                          │
│  Nothing crosses this boundary ──────────│──── No data egress
└──────────────────────────────────────────┘
```

### What KYRA Never Does

- Never executes scanned code
- Never modifies scanned files
- Never stores actual cryptographic keys or secrets
- Never makes network requests during analysis
- Never requires authentication or accounts for local use
- Never sends usage analytics

### Threat Model for the Scanner Itself

| Threat | Mitigation |
|--------|-----------|
| Malicious file designed to crash scanner | Per-file timeout + exception handling. Invalid files are skipped with a warning. |
| Symlink to `/etc/shadow` or sensitive paths | Symlink resolution + scan root boundary enforcement. |
| Extremely large repository | File size limits + content hash caching + configurable max files. |
| Scanner dependency has vulnerability | Minimal dependencies. `cryptography` library (well-audited). Pin versions. |

---

## 10. DEVELOPMENT ROADMAP

### 6-Week MVP Plan

#### Week 1: Foundation

**Goal:** Project scaffolding, scanner foundation, first detection.

- [ ] Project setup: `pyproject.toml`, pytest, linting (ruff), CI with GitHub Actions
- [ ] File walker with `.gitignore` and `.kyraignore` support
- [ ] SHA-256 content hash caching in SQLite
- [ ] Regex detector with 10 initial rules (RSA, AES, SHA-1, SHA-256, ECDSA, DES, MD5, DH, ChaCha20, 3DES)
- [ ] Tests with fixture files containing known crypto patterns

**Verification (Checkpoint Eval pattern):** Scanner correctly identifies crypto in 5 test fixture files with zero false negatives.

#### Week 2: Scanner Depth

**Goal:** AST parser, config parser, certificate analyzer.

- [ ] Python AST detector: `cryptography`, `PyCryptodome`, `hashlib`, `ssl` imports
- [ ] TLS config parser: nginx, Apache common patterns
- [ ] X.509 certificate analyzer (read public data only)
- [ ] Scanner engine that orchestrates all detectors
- [ ] Finding deduplication (same crypto found by multiple detectors)

**Verification:** Scanner runs on 3 real open-source projects and produces reasonable output.

#### Week 3: CBOM + Data Layer

**Goal:** Structured CBOM output, SQLite persistence.

- [ ] Pydantic CBOM schema (as designed in section 4)
- [ ] CBOM generator: transforms raw findings → structured CBOM entries
- [ ] Auto-classification of `pq_readiness` based on algorithm lookup table
- [ ] JSON and CSV export
- [ ] SQLite storage: scan history, CBOM snapshots
- [ ] Scan diffing: what changed between two scans

**Verification:** Generated CBOM validates against schema. Export/import round-trips without data loss.

#### Week 4: Risk Engine + CLI

**Goal:** HNDL scoring, CLI interface, CI integration.

- [ ] Risk scoring engine implementing the formula from section 6
- [ ] Algorithm risk lookup table
- [ ] Data lifetime and exposure heuristics (inferred from file paths and usage context)
- [ ] Upgrade recommendation mapping
- [ ] Typer CLI: `scan`, `cbom generate`, `risk analyze`
- [ ] `--fail-on-risk` flag for CI
- [ ] Rich terminal output (tables, colors)

**Verification:** Risk scores for test fixtures match manually calculated expected values. CLI exit codes work correctly.

#### Week 5: Dashboard

**Goal:** Web UI for visualization.

- [ ] FastAPI backend with API endpoints from section 8
- [ ] React app: overview dashboard, findings table, risk breakdown charts
- [ ] Finding detail view with code snippet context
- [ ] Upgrade recommendations page
- [ ] Build React → static files, serve from FastAPI
- [ ] `kyra dashboard` command to launch

**Verification:** Dashboard loads, displays data from a real scan, all charts render.

#### Week 6: Polish + Hardening

**Goal:** Documentation, edge cases, packaging.

- [ ] Test on 5+ real open-source repositories of varying sizes
- [ ] Handle edge cases: empty repos, binary-only repos, monorepos
- [ ] pypi packaging (`pip install kyra`)
- [ ] README with quickstart, screenshots
- [ ] Security self-review (no private key leaking, no path traversal, no injection)
- [ ] Performance: scan a 10k-file repo in under 30 seconds
- [ ] Add Java and JavaScript regex rules (expand language coverage)

**Verification:** Full pipeline test: `kyra scan . && kyra cbom generate && kyra risk analyze && kyra dashboard` works end-to-end.

### If Time Available: Weeks 7–8 (Buffer / Enhancement)

- [ ] GitHub Action: `kyra-action` for easy CI integration
- [ ] `.kyra.yaml` configuration file (custom rules, thresholds, exclusions)
- [ ] SARIF output format (GitHub code scanning integration)
- [ ] Additional language support: Go, Rust, C/C++ (regex-based)
- [ ] Scan comparison over time in dashboard (trend lines)

### Development Practices (from `everything-claude-code` patterns)

| Practice | How Applied |
|----------|------------|
| **TDD Workflow** | Every scanner rule ships with positive test (should match) and negative test (should not match). Risk engine has expected-value tests for known inputs. |
| **Verification Loops** | End of each week: run full pipeline on real repos. Compare output to manual analysis. Fix discrepancies before moving on. |
| **Content Hash Caching** | Implemented in Week 1 — enables fast re-scanning throughout development. |
| **Rules Architecture** | Detection patterns are YAML, not code. Adding a new algorithm pattern is a data change, not a code change. |
| **Research-First** | Before building each component, scan 3–5 existing tools (crydetect, cbomkit, etc.) to understand prior art. Don't reinvent what's already solved. |
| **Quality Gates** | CI runs: linting (ruff), type checking (mypy), tests (pytest --cov ≥ 80%), security scan on dependencies. |
| **Session State Tracking** | Development journal in `docs/devlog.md` — decisions, trade-offs, blockers. Prevents context loss across long development sessions. |

---

## Summary

KYRA MVP is a single Python package that scans code for cryptographic usage, generates a standardized inventory (CBOM), calculates harvest-now-decrypt-later risk, and visualizes results in a local dashboard. It runs entirely on the user's machine with no network dependency. The architecture is a simple linear pipeline (scan → structure → score → display) that a single developer can build, test, and ship in 6 weeks.

The moat is not in complexity — it's in being the first open-source tool that connects crypto discovery directly to quantified quantum risk with actionable upgrade paths. Every security team will need this within 3 years. KYRA gives them a starting point today.
