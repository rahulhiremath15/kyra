# KYRA GitHub Action

Official GitHub Action for running [KYRA](https://github.com/kyra-security/kyra) - Post-Quantum Cryptography Readiness Scanner.

## Features

- 🔍 Automatic cryptographic usage detection
- 📊 CBOM (Cryptography Bill of Materials) generation
- ⚠️ HNDL (Harvest-Now Decrypt-Later) risk assessment
- 🚨 Configurable risk-based build gates
- 📁 Artifact uploads with retention
- 🔢 Structured outputs for further analysis

## Usage

### Basic Scan

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  kyra-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run KYRA security scan
        uses: ./.github/actions/kyra-scan
        with:
          path: .
```

### Fail on High Risk

```yaml
- name: Run KYRA security scan
  uses: ./.github/actions/kyra-scan
  with:
    path: .
    fail-on-risk: high
```

### Custom Output Format

```yaml
- name: Run KYRA security scan
  uses: ./.github/actions/kyra-scan
  with:
    path: .
    format: cyclonedx
    output-file: sbom-crypto.json
```

### Using Outputs

```yaml
- name: Run KYRA security scan
  id: kyra
  uses: ./.github/actions/kyra-scan
  with:
    path: .

- name: Check results
  run: |
    echo "Readiness Score: ${{ steps.kyra.outputs.risk_score }}/100"
    echo "Total Findings: ${{ steps.kyra.outputs.finding_count }}"
    echo "Critical Issues: ${{ steps.kyra.outputs.critical_count }}"
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `path` | Directory to scan for cryptographic usage | No | `.` |
| `fail-on-risk` | Fail the build if any finding meets this risk level (`low`, `medium`, `high`, `critical`) | No | _(none)_ |
| `format` | Output format for the report (`json`, `csv`, `cyclonedx`) | No | `json` |
| `output-file` | Path to save the structured report output | No | `kyra-report.json` |
| `python-version` | Python version to use for running KYRA | No | `3.11` |
| `kyra-ref` | KYRA git ref to install (branch, tag, or commit SHA) | No | `main` |
| `install-from-pypi` | Install from PyPI instead of GitHub | No | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `risk_score` | Post-quantum readiness score (0-100) |
| `finding_count` | Total number of cryptographic findings detected |
| `critical_count` | Number of critical risk findings |
| `high_count` | Number of high risk findings |
| `medium_count` | Number of medium risk findings |
| `low_count` | Number of low risk findings |
| `overall_risk` | Overall risk level (LOW, MEDIUM, HIGH, CRITICAL) |

## Advanced Examples

### Multi-step workflow with conditional steps

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run KYRA scan
        id: scan
        uses: ./.github/actions/kyra-scan
        with:
          path: .
          format: json

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const score = '${{ steps.scan.outputs.risk_score }}';
            const critical = '${{ steps.scan.outputs.critical_count }}';
            const high = '${{ steps.scan.outputs.high_count }}';

            const body = `## 🛡️ KYRA Security Scan Results

            **Readiness Score:** ${score}/100
            **Critical Issues:** ${critical}
            **High Risk Issues:** ${high}

            [View full report in artifacts](${context.payload.repository.html_url}/actions/runs/${context.runId})`;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });

      - name: Fail on critical findings
        if: steps.scan.outputs.critical_count > 0
        run: |
          echo "::error::Critical security findings detected!"
          exit 1
```

### Matrix testing across multiple directories

```yaml
jobs:
  scan-matrix:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        component: [api, frontend, backend]
    steps:
      - uses: actions/checkout@v4

      - name: Scan ${{ matrix.component }}
        uses: ./.github/actions/kyra-scan
        with:
          path: ./services/${{ matrix.component }}
          fail-on-risk: high
          output-file: kyra-${{ matrix.component }}.json
```

## Installation

By default, this action installs KYRA directly from the GitHub repository:
```bash
pip install git+https://github.com/rahulhiremath15/kyra.git@main
```

### Using a Specific Version

To use a specific version, set the `kyra-ref` input:

```yaml
- name: Run KYRA security scan
  uses: ./.github/actions/kyra-scan
  with:
    path: .
    kyra-ref: v1.0.0  # Use a specific tag
```

### Installing from PyPI (Once Published)

Once KYRA is published to PyPI, you can install from there by setting `install-from-pypi: true`:

```yaml
- name: Run KYRA security scan
  uses: ./.github/actions/kyra-scan
  with:
    path: .
    install-from-pypi: true
```

> **⚠️ Important:** Installing from PyPI requires KYRA to be officially published. Until then, the action will use the GitHub repository (default behavior).

## Requirements

- Python 3.11+ (configurable via `python-version` input)
- KYRA is installed automatically from GitHub (default) or PyPI (when published)

## License

MIT
