#!/bin/bash
set -euo pipefail

DOMAINS_FILE="${DOMAINS_FILE:-domains.txt}"
OUTPUT_FILE="${OUTPUT_FILE:-testssl-results.json}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-120}"
TESTSSL_PATH="${TESTSSL_PATH:-./testssl-repo/testssl.sh}"

echo "Scanning with $TESTSSL_PATH → domain, IPs, TLS versions, ciphers only"

if [[ ! -f "$DOMAINS_FILE" ]]; then
  echo "❌ $DOMAINS_FILE not found!"
  exit 1
fi

mapfile -t DOMAINS < "$DOMAINS_FILE"
RESULTS=()

for DOMAIN in "${DOMAINS[@]}"; do
  DOMAIN=$(echo "$DOMAIN" | xargs)
  [[ -z "$DOMAIN" ]] && continue

  echo "Scanning $DOMAIN..."
  TEMP_JSON=$(mktemp)

  # Basic scan → reliable JSON every time
  if timeout "${SCAN_TIMEOUT}s" "$TESTSSL_PATH" \
    --jsonfile "$TEMP_JSON" \
    --quiet \
    --warnings off \
    "$DOMAIN"; then
    
    DOMAIN_CLEAN=$(echo "$DOMAIN" | sed 's/:443$//')
    
    # 1. Domain (cleaned)
    # 2. IP addresses (primary IP)
    IP=$(jq -r '.ip // "unknown"' "$TEMP_JSON" 2>/dev/null || echo "unknown")
    
    # 3. TLS versions (unique supported protocols)
    TLS_VERSIONS=$(jq -r '[.findings[] | select(.id=="protocols")] | map(.finding | split(" ")[0]) | unique | join(", ")' "$TEMP_JSON" 2>/dev/null || echo "unknown")
    
    # 4. Ciphers (all cipher findings, comma-separated)
    CIPHERS=$(jq -r '[.findings[] | select(.id=="ciphers")] | map(.finding) | join(", ")' "$TEMP_JSON" 2>/dev/null || echo "none")
    
    RESULTS+=("{
      \"domain\": \"${DOMAIN_CLEAN}\",
      \"ip_addresses\": \"${IP}\",
      \"tls_versions_supported\": \"${TLS_VERSIONS}\",
      \"list_of_ciphers\": \"${CIPHERS}\"
    }")
    
    echo "✅ $DOMAIN | TLS: $TLS_VERSIONS"
  else
    echo "❌ $DOMAIN failed"
    RESULTS+=("{
      \"domain\": \"${DOMAIN}\",
      \"ip_addresses\": \"timeout\",
      \"tls_versions_supported\": \"failed\",
      \"list_of_ciphers\": \"\"
    }")
  fi

  rm -f "$TEMP_JSON"
done

[[ ${#RESULTS[@]} -eq 0 ]] && { echo "❌ No results"; exit 1; }

printf '%s\n' "${RESULTS[@]}" | jq -s . > "$OUTPUT_FILE"
echo "✅ $(jq 'length' "$OUTPUT_FILE") results → $OUTPUT_FILE"

# Show first result
jq '.[0]' "$OUTPUT_FILE"
