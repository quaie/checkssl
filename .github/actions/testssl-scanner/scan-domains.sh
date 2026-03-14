#!/bin/bash
set -euo pipefail

DOMAINS_FILE="${DOMAINS_FILE:-domains.txt}"
OUTPUT_FILE="${OUTPUT_FILE:-testssl-results.json}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-60}"

echo "Scanning domains from $DOMAINS_FILE..."

if [[ ! -f "$DOMAINS_FILE" ]]; then
  echo "Error: $DOMAINS_FILE not found!"
  exit 1
fi

mapfile -t DOMAINS < "$DOMAINS_FILE"
RESULTS=()

for DOMAIN in "${DOMAINS[@]}"; do
  DOMAIN=$(echo "$DOMAIN" | xargs)
  [[ -z "$DOMAIN" ]] && continue

  echo "Scanning $DOMAIN..."
  TEMP_JSON=$(mktemp)

  if timeout "${SCAN_TIMEOUT}"s ./testssl.sh --jsonfile "$TEMP_JSON" --quiet --warnings off "$DOMAIN"; then
    DOMAIN_CLEAN=$(echo "$DOMAIN" | sed 's/:443$//')
    IP=$(jq -r '.ip // "unknown"' "$TEMP_JSON" 2>/dev/null || echo "unknown")
    GRADE=$(jq -r '.grade.overall // "unknown"' "$TEMP_JSON" 2>/dev/null || echo "unknown")
    CIPHERS=$(jq -r '[.findings[]? | select(.id=="ciphers")] | map(.finding) | join(", ") // empty' "$TEMP_JSON" 2>/dev/null || echo "")

    RESULTS+=("{
      \"domain\": \"${DOMAIN_CLEAN}\",
      \"ip_addresses\": \"${IP}\",
      \"grade\": \"${GRADE}\",
      \"cipher_types\": \"${CIPHERS}\"
    }")
  else
    echo "Scan failed for $DOMAIN"
  fi

  rm -f "$TEMP_JSON"
done

if [[ ${#RESULTS[@]} -eq 0 ]]; then
  echo "Error: no scan results were produced. Check testssl.sh output or domains.txt."
  exit 1
fi

printf '%s\n' "${RESULTS[@]}" | jq -s . > "$OUTPUT_FILE"
echo "Saved $(jq 'length' "$OUTPUT_FILE") results to $OUTPUT_FILE"
