"""Fixtures shared across scanner tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """Create a minimal fake repository with known crypto patterns."""

    # -- Python file with RSA and SHA-1 --
    auth_dir = tmp_path / "backend" / "auth"
    auth_dir.mkdir(parents=True)
    (auth_dir / "jwt.py").write_text(
        "from Crypto.PublicKey import RSA\n"
        "\n"
        "def create_key():\n"
        "    key = RSA.generate(2048)\n"
        "    return key\n",
        encoding="utf-8",
    )

    utils_dir = tmp_path / "backend" / "utils"
    utils_dir.mkdir(parents=True)
    (utils_dir / "hash.py").write_text(
        "import hashlib\n"
        "\n"
        "def hash_file(data: bytes) -> str:\n"
        "    return hashlib.sha1(data).hexdigest()\n",
        encoding="utf-8",
    )

    # -- Config file with TLS cipher suite --
    nginx_dir = tmp_path / "nginx"
    nginx_dir.mkdir()
    (nginx_dir / "nginx.conf").write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        "}\n",
        encoding="utf-8",
    )

    # -- File with AES-256-GCM (quantum-safe) --
    storage_dir = tmp_path / "backend" / "storage"
    storage_dir.mkdir(parents=True)
    (storage_dir / "encrypt.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "\n"
        "def encrypt(plaintext: bytes, key: bytes) -> bytes:\n"
        "    # Using AES-256-GCM for data at rest\n"
        "    aesgcm = AESGCM(key)  # AES-256 key\n"
        "    return aesgcm.encrypt(nonce, plaintext, None)\n",
        encoding="utf-8",
    )

    # -- File with post-quantum algorithm (should be detected) --
    pqc_dir = tmp_path / "backend" / "pqc"
    pqc_dir.mkdir(parents=True)
    (pqc_dir / "hybrid.py").write_text(
        "# Hybrid key exchange using ML-KEM + X25519\n"
        "def hybrid_exchange():\n"
        "    kem = MLKEM.generate_keypair()\n"
        "    return kem\n",
        encoding="utf-8",
    )

    # -- Binary file (should be skipped) --
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

    # -- Private key file (should be skipped by engine) --
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "server.key").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH...\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    # -- .gitignore --
    (tmp_path / ".gitignore").write_text(
        "secrets/\n*.log\n",
        encoding="utf-8",
    )

    # -- A file that should be ignored --
    (tmp_path / "debug.log").write_text(
        "RSA-2048 key generated\n",
        encoding="utf-8",
    )

    # -- Empty file (should be skipped) --
    (tmp_path / "empty.py").write_text("", encoding="utf-8")

    return tmp_path


@pytest.fixture
def sample_python_with_crypto() -> str:
    """Python source containing known crypto patterns."""
    return (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "import hashlib\n"
        "\n"
        "# Generate RSA-4096 key\n"
        "private_key = rsa.generate_private_key(\n"
        "    public_exponent=65537,\n"
        "    key_size=4096,\n"
        ")\n"
        "\n"
        "digest = hashlib.md5(b'test').hexdigest()\n"
        "digest2 = hashlib.sha256(b'test').hexdigest()\n"
    )
