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

  # Count findings by risk level
  CRITICAL_COUNT=$(jq -r '[.risk.findings[] | select(.risk_level == "CRITICAL")] | length' "$OUTPUT_FILE")
  HIGH_COUNT=$(jq -r '[.risk.findings[] | select(.risk_level == "HIGH")] | length' "$OUTPUT_FILE")
  MEDIUM_COUNT=$(jq -r '[.risk.findings[] | select(.risk_level == "MEDIUM")] | length' "$OUTPUT_FILE")
  LOW_COUNT=$(jq -r '[.risk.findings[] | select(.risk_level == "LOW")] | length' "$OUTPUT_FILE")

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

  # Check fail-on-risk threshold
  if [ -n "$FAIL_ON_RISK" ]; then
    FAIL_LEVEL_UPPER=$(echo "$FAIL_ON_RISK" | tr '[:lower:]' '[:upper:]')

    # Define risk level ordering
    declare -A RISK_ORDER
    RISK_ORDER[LOW]=0
    RISK_ORDER[MEDIUM]=1
    RISK_ORDER[HIGH]=2
    RISK_ORDER[CRITICAL]=3

    # Check if any findings meet or exceed the threshold
    THRESHOLD_ORDER=${RISK_ORDER[$FAIL_LEVEL_UPPER]}

    if [ -z "$THRESHOLD_ORDER" ]; then
      echo "::error::Invalid fail-on-risk level: $FAIL_ON_RISK (must be low, medium, high, or critical)"
      exit 2
    fi

    SHOULD_FAIL=false

    # Check each risk level against threshold
    if [ "${RISK_ORDER[CRITICAL]}" -ge "$THRESHOLD_ORDER" ] && [ "$CRITICAL_COUNT" -gt 0 ]; then
      SHOULD_FAIL=true
    fi
    if [ "${RISK_ORDER[HIGH]}" -ge "$THRESHOLD_ORDER" ] && [ "$HIGH_COUNT" -gt 0 ]; then
      SHOULD_FAIL=true
    fi
    if [ "${RISK_ORDER[MEDIUM]}" -ge "$THRESHOLD_ORDER" ] && [ "$MEDIUM_COUNT" -gt 0 ]; then
      SHOULD_FAIL=true
    fi
    if [ "${RISK_ORDER[LOW]}" -ge "$THRESHOLD_ORDER" ] && [ "$LOW_COUNT" -gt 0 ]; then
      SHOULD_FAIL=true
    fi

    if [ "$SHOULD_FAIL" = true ]; then
      echo "::error::Risk gate failed: findings at or above $FAIL_LEVEL_UPPER level detected"
      echo "::error::Critical: $CRITICAL_COUNT | High: $HIGH_COUNT | Medium: $MEDIUM_COUNT | Low: $LOW_COUNT"
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
