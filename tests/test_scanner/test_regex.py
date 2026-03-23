"""Tests for the regex detector."""

from __future__ import annotations

from kyra.scanner.detectors.regex import RegexDetector


class TestRegexDetector:
    """Tests for RegexDetector with built-in rules."""

    def setup_method(self) -> None:
        self.detector = RegexDetector()

    def test_loads_rules(self) -> None:
        """Detector should load rules from default YAML files."""
        assert self.detector.rule_count > 0

    def test_name(self) -> None:
        assert self.detector.name == "regex"

    # ------------------------------------------------------------------
    # True positives — things that SHOULD match
    # ------------------------------------------------------------------

    def test_detects_rsa_generate(self) -> None:
        content = "key = RSA.generate(2048)\n"
        findings = self.detector.scan_file("test.py", content)
        rsa = [f for f in findings if f.algorithm_family == "RSA"]
        assert len(rsa) >= 1
        assert rsa[0].key_size == 2048

    def test_detects_rsa_reference(self) -> None:
        content = "# Use RSA-4096 for signing\n"
        findings = self.detector.scan_file("readme.md", content)
        rsa = [f for f in findings if f.algorithm_family == "RSA"]
        assert len(rsa) >= 1
        assert rsa[0].key_size == 4096

    def test_detects_aes_256(self) -> None:
        content = "cipher = AES-256 encryption\n"
        findings = self.detector.scan_file("config.yaml", content)
        aes = [f for f in findings if f.algorithm_family == "AES"]
        assert len(aes) >= 1
        assert aes[0].key_size == 256

    def test_detects_aes_gcm(self) -> None:
        content = "using AES-256-GCM mode\n"
        findings = self.detector.scan_file("test.py", content)
        aes = [f for f in findings if f.algorithm_family == "AES"]
        assert len(aes) >= 1

    def test_detects_sha1(self) -> None:
        content = "digest = hashlib.sha1(data)\n"
        findings = self.detector.scan_file("test.py", content)
        sha1 = [f for f in findings if f.algorithm_family == "SHA-1"]
        assert len(sha1) >= 1

    def test_detects_sha256(self) -> None:
        content = "h = SHA256.new(data)\n"
        findings = self.detector.scan_file("test.py", content)
        sha2 = [f for f in findings if f.algorithm_family == "SHA-2"]
        assert len(sha2) >= 1

    def test_detects_md5(self) -> None:
        content = "checksum = md5(payload)\n"
        findings = self.detector.scan_file("test.py", content)
        md5 = [f for f in findings if f.algorithm_family == "MD5"]
        assert len(md5) >= 1

    def test_detects_ecdsa(self) -> None:
        content = "signer = ECDSA.new(key)\n"
        findings = self.detector.scan_file("test.py", content)
        ecc = [f for f in findings if f.algorithm_family == "ECC"]
        assert len(ecc) >= 1

    def test_detects_ecdh(self) -> None:
        content = "kex = ECDHE key exchange\n"
        findings = self.detector.scan_file("test.py", content)
        ecc = [f for f in findings if f.algorithm_family == "ECC"]
        assert len(ecc) >= 1

    def test_detects_chacha20(self) -> None:
        content = "cipher = ChaCha20.new(key=key)\n"
        findings = self.detector.scan_file("test.py", content)
        cc = [f for f in findings if f.algorithm_family == "ChaCha20"]
        assert len(cc) >= 1

    def test_detects_triple_des(self) -> None:
        content = "cipher = 3DES.new(key)\n"
        findings = self.detector.scan_file("test.py", content)
        tdes = [f for f in findings if f.algorithm_family == "3DES"]
        assert len(tdes) >= 1

    def test_detects_dh(self) -> None:
        content = "params = DH-2048 parameters\n"
        findings = self.detector.scan_file("test.py", content)
        dh = [f for f in findings if f.algorithm_family == "DH"]
        assert len(dh) >= 1
        assert dh[0].key_size == 2048

    def test_detects_mlkem(self) -> None:
        content = "kem = ML-KEM encapsulate()\n"
        findings = self.detector.scan_file("test.py", content)
        pqc = [f for f in findings if f.algorithm_family == "ML-KEM"]
        assert len(pqc) >= 1

    def test_detects_mldsa(self) -> None:
        content = "sig = ML-DSA sign(msg)\n"
        findings = self.detector.scan_file("test.py", content)
        pqc = [f for f in findings if f.algorithm_family == "ML-DSA"]
        assert len(pqc) >= 1

    def test_detects_slhdsa(self) -> None:
        content = "sig = SLH-DSA sign(msg)\n"
        findings = self.detector.scan_file("test.py", content)
        pqc = [f for f in findings if f.algorithm_family == "SLH-DSA"]
        assert len(pqc) >= 1

    # ------------------------------------------------------------------
    # Line number accuracy
    # ------------------------------------------------------------------

    def test_correct_line_number(self) -> None:
        content = "line1\nline2\nRSA.generate(4096)\nline4\n"
        findings = self.detector.scan_file("test.py", content)
        rsa = [f for f in findings if f.algorithm_family == "RSA"]
        assert len(rsa) >= 1
        assert rsa[0].line_number == 3

    # ------------------------------------------------------------------
    # True negatives — things that should NOT match
    # ------------------------------------------------------------------

    def test_no_false_positive_on_description(self) -> None:
        """The word 'DESCRIPTION' should not trigger DES detection."""
        content = 'DESCRIPTION = "A package description"\n'
        findings = self.detector.scan_file("setup.py", content)
        des = [f for f in findings if f.algorithm_family == "DES"]
        assert len(des) == 0

    def test_no_false_positive_on_desktop(self) -> None:
        content = "DESKTOP_SESSION=gnome\n"
        findings = self.detector.scan_file("env.sh", content)
        des = [f for f in findings if f.algorithm_family == "DES"]
        assert len(des) == 0

    def test_empty_file(self) -> None:
        findings = self.detector.scan_file("empty.py", "")
        assert findings == []

    # ------------------------------------------------------------------
    # Multiple findings per file
    # ------------------------------------------------------------------

    def test_multiple_findings_same_file(self) -> None:
        content = (
            "from Crypto.PublicKey import RSA\n"
            "key = RSA.generate(2048)\n"
            "digest = hashlib.sha1(data)\n"
            "h = hashlib.md5(payload)\n"
        )
        findings = self.detector.scan_file("multi.py", content)
        families = {f.algorithm_family for f in findings}
        assert "RSA" in families
        assert "SHA-1" in families
        assert "MD5" in families

    # ------------------------------------------------------------------
    # Custom rules directory
    # ------------------------------------------------------------------

    def test_custom_rules_dir(self, tmp_path) -> None:
        """Detector should load rules from a custom directory."""
        rules_file = tmp_path / "custom.yaml"
        rules_file.write_text(
            "- id: custom-test\n"
            '  pattern: "CUSTOM_CRYPTO"\n'
            "  algorithm_family: CUSTOM\n"
            "  confidence: 0.99\n"
            '  description: "Custom test rule"\n',
            encoding="utf-8",
        )
        det = RegexDetector(rules_dirs=[tmp_path])
        findings = det.scan_file("test.py", "using CUSTOM_CRYPTO here\n")
        assert len(findings) == 1
        assert findings[0].algorithm_family == "CUSTOM"
        assert findings[0].confidence == 0.99

    def test_malformed_rule_skipped(self, tmp_path) -> None:
        """A bad rule should not crash the detector."""
        rules_file = tmp_path / "bad.yaml"
        rules_file.write_text(
            # Missing required fields
            "- id: broken\n"
            '  pattern: "[invalid regex"\n'
            "  algorithm_family: BROKEN\n"
            "  confidence: 0.5\n"
            '  description: "broken"\n'
            "- id: good\n"
            '  pattern: "GOOD_PATTERN"\n'
            "  algorithm_family: GOOD\n"
            "  confidence: 0.8\n"
            '  description: "good"\n',
            encoding="utf-8",
        )
        det = RegexDetector(rules_dirs=[tmp_path])
        # The broken rule is skipped, the good rule still loads.
        assert det.rule_count == 1
        findings = det.scan_file("test.py", "GOOD_PATTERN\n")
        assert len(findings) == 1
