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
  # Extract metrics directly from Kyra's root JSON structure
  RISK_SCORE=$(jq -r '.overall_risk // 0' "$OUTPUT_FILE")
  FINDING_COUNT=$(jq -r '.total_findings // 0' "$OUTPUT_FILE")
  OVERALL_RISK=$(jq -r '.overall_level // "LOW"' "$OUTPUT_FILE")

  # Extract counts directly from counts_by_level (fallback to 0 if missing)
  CRITICAL_COUNT=$(jq -r '.counts_by_level.CRITICAL // 0' "$OUTPUT_FILE")
  HIGH_COUNT=$(jq -r '.counts_by_level.HIGH // 0' "$OUTPUT_FILE")
  MEDIUM_COUNT=$(jq -r '.counts_by_level.MEDIUM // 0' "$OUTPUT_FILE")
  LOW_COUNT=$(jq -r '.counts_by_level.LOW // 0' "$OUTPUT_FILE")

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
    SHOULD_FAIL=false

    case "$FAIL_LEVEL_UPPER" in
      "CRITICAL")
        if [ "$CRITICAL_COUNT" -gt 0 ]; then SHOULD_FAIL=true; fi
        ;;
      "HIGH")
        if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then SHOULD_FAIL=true; fi
        ;;
      "MEDIUM")
        if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ] || [ "$MEDIUM_COUNT" -gt 0 ]; then SHOULD_FAIL=true; fi
        ;;
      "LOW")
        if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ] || [ "$MEDIUM_COUNT" -gt 0 ] || [ "$LOW_COUNT" -gt 0 ]; then SHOULD_FAIL=true; fi
        ;;
      *)
        echo "::error::Invalid fail-on-risk level: $FAIL_ON_RISK"
        exit 2
        ;;
    esac

    if [ "$SHOULD_FAIL" = "true" ]; then
      echo "::error::Risk gate failed: findings at or above $FAIL_LEVEL_UPPER level detected"
      echo "::error::Critical: $CRITICAL_COUNT | High: $HIGH_COUNT | Medium: $MEDIUM_COUNT | Low: $LOW_COUNT"
      exit 1
    else
      echo "✅ Risk gate passed: no findings at or above $FAIL_LEVEL_UPPER level"
      echo "Counts -> Critical: $CRITICAL_COUNT | High: $HIGH_COUNT | Medium: $MEDIUM_COUNT | Low: $LOW_COUNT"
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
