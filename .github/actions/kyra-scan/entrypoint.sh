#!/bin/bash
set -e

# GitHub Actions input variables
PATH_TO_SCAN="${INPUT_PATH:-.}"
FAIL_ON_RISK="${INPUT_FAIL_ON_RISK}"
FORMAT="${INPUT_FORMAT:-json}"
OUTPUT_FILE="${INPUT_OUTPUT_FILE:-kyra-report.json}"

echo "::group::KYRA Scan Configuration"
echo "Path: $PATH_TO_SCAN"
echo "Fail on risk: ${FAIL_ON_RISK:-none}"
echo "Format: $FORMAT"
echo "Output file: $OUTPUT_FILE"
echo "::endgroup::"

# Run KYRA scan with structured output
echo "::group::Running KYRA scan"
kyra report "$PATH_TO_SCAN" --format "$FORMAT" --output "$OUTPUT_FILE"
echo "::endgroup::"

# Parse the JSON report to extract metrics
if [ "$FORMAT" = "json" ]; then
  # Extract metrics using jq (handling structured JSON report)
  RISK_SCORE=$(jq -r '.summary.readiness_score // 0' "$OUTPUT_FILE")
  FINDING_COUNT=$(jq -r '.summary.total_findings // 0' "$OUTPUT_FILE")
  OVERALL_RISK=$(jq -r '.risk.overall_level // "LOW"' "$OUTPUT_FILE")

  # Count findings by risk level (safely handling null arrays)
  CRITICAL_COUNT=$(jq -r '[.risk.findings[]? | select(.risk_level == "CRITICAL")] | length' "$OUTPUT_FILE")
  HIGH_COUNT=$(jq -r '[.risk.findings[]? | select(.risk_level == "HIGH")] | length' "$OUTPUT_FILE")
  MEDIUM_COUNT=$(jq -r '[.risk.findings[]? | select(.risk_level == "MEDIUM")] | length' "$OUTPUT_FILE")
  LOW_COUNT=$(jq -r '[.risk.findings[]? | select(.risk_level == "LOW")] | length' "$OUTPUT_FILE")

  echo "::group::Scan Results"
  echo "Readiness Score: $RISK_SCORE/100"
  echo "Total Findings: $FINDING_COUNT"
  echo "Overall Risk: $OVERALL_RISK"
  echo "Critical: $CRITICAL_COUNT | High: $HIGH_COUNT | Medium: $MEDIUM_COUNT | Low: $LOW_COUNT"
  echo "::endgroup::"

  # Set GitHub Actions outputs
  echo "risk_score=$RISK_SCORE" >> "$GITHUB_OUTPUT"
  echo "finding_count=$FINDING_COUNT" >> "$GITHUB_OUTPUT"
  echo "critical_count=$CRITICAL_COUNT" >> "$GITHUB_OUTPUT"
  echo "high_count=$HIGH_COUNT" >> "$GITHUB_OUTPUT"
  echo "medium_count=$MEDIUM_COUNT" >> "$GITHUB_OUTPUT"
  echo "low_count=$LOW_COUNT" >> "$GITHUB_OUTPUT"
  echo "overall_risk=$OVERALL_RISK" >> "$GITHUB_OUTPUT"

  # --- RISK GATE LOGIC ---
  if [ -n "$FAIL_ON_RISK" ]; then
    FAIL_LEVEL_UPPER=$(echo "$FAIL_ON_RISK" | tr '[:lower:]' '[:upper:]')

    # Force counts to be integers (default 0)
    C_COUNT=${CRITICAL_COUNT:-0}
    H_COUNT=${HIGH_COUNT:-0}
    M_COUNT=${MEDIUM_COUNT:-0}
    L_COUNT=${LOW_COUNT:-0}

    SHOULD_FAIL=false

    case "$FAIL_LEVEL_UPPER" in
      "CRITICAL")
        if [ "$C_COUNT" -gt 0 ]; then SHOULD_FAIL=true; fi
        ;;
      "HIGH")
        if [ "$C_COUNT" -gt 0 ] || [ "$H_COUNT" -gt 0 ]; then SHOULD_FAIL=true; fi
        ;;
      "MEDIUM")
        if [ "$C_COUNT" -gt 0 ] || [ "$H_COUNT" -gt 0 ] || [ "$M_COUNT" -gt 0 ]; then SHOULD_FAIL=true; fi
        ;;
      "LOW")
        if [ "$C_COUNT" -gt 0 ] || [ "$H_COUNT" -gt 0 ] || [ "$M_COUNT" -gt 0 ] || [ "$L_COUNT" -gt 0 ]; then SHOULD_FAIL=true; fi
        ;;
      *)
        echo "::error::Invalid fail-on-risk level: $FAIL_ON_RISK (must be low, medium, high, or critical)"
        exit 2
        ;;
    esac

    if [ "$SHOULD_FAIL" = true ]; then
      echo "::error::Risk gate failed: findings at or above $FAIL_LEVEL_UPPER level detected"
      echo "::error::Critical: $C_COUNT | High: $H_COUNT | Medium: $M_COUNT | Low: $L_COUNT"
      exit 1
    else
      echo "✅ Risk gate passed: no findings at or above $FAIL_LEVEL_UPPER level"
    fi
  fi
else
  # For non-JSON formats, provide basic outputs
  echo "risk_score=0" >> "$GITHUB_OUTPUT"
  echo "finding_count=0" >> "$GITHUB_OUTPUT"
  echo "critical_count=0" >> "$GITHUB_OUTPUT"
  echo "high_count=0" >> "$GITHUB_OUTPUT"
  echo "medium_count=0" >> "$GITHUB_OUTPUT"
  echo "low_count=0" >> "$GITHUB_OUTPUT"
  echo "overall_risk=UNKNOWN" >> "$GITHUB_OUTPUT"
fi

echo "✅ KYRA scan completed successfully"
