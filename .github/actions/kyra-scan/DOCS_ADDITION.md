# GitHub Action Usage

Add the following section to your main README.md to document the GitHub Action:

---

## GitHub Action

KYRA can be integrated into your CI/CD pipeline using the official GitHub Action.

### Quick Start

Add KYRA scanning to your workflow:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  kyra-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run KYRA security scan
        uses: ./.github/actions/kyra-scan
        with:
          path: .
          fail-on-risk: high
```

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan | `.` |
| `fail-on-risk` | Fail build on risk level (low/medium/high/critical) | _(none)_ |
| `format` | Report format (json/csv/cyclonedx) | `json` |
| `output-file` | Output file path | `kyra-report.json` |
| `python-version` | Python version | `3.11` |
| `kyra-ref` | Git ref to install (branch/tag/SHA) | `main` |
| `install-from-pypi` | Install from PyPI instead of GitHub | `false` |

> **Note:** By default, KYRA is installed from GitHub. Once published to PyPI, you can set `install-from-pypi: true`.

### Outputs

| Output | Description |
|--------|-------------|
| `risk_score` | Readiness score (0-100) |
| `finding_count` | Total findings |
| `critical_count` | Critical findings |
| `high_count` | High risk findings |
| `medium_count` | Medium risk findings |
| `low_count` | Low risk findings |
| `overall_risk` | Overall risk level |

### Example: PR Comments

```yaml
- name: Run KYRA scan
  id: scan
  uses: ./.github/actions/kyra-scan
  with:
    path: .

- name: Comment results on PR
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      const score = '${{ steps.scan.outputs.risk_score }}';
      const findings = '${{ steps.scan.outputs.finding_count }}';
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: `## 🛡️ KYRA Scan Results\n\n**Score:** ${score}/100\n**Findings:** ${findings}`
      });
```

For more examples and advanced usage, see [`.github/actions/kyra-scan/README.md`](.github/actions/kyra-scan/README.md).

---
