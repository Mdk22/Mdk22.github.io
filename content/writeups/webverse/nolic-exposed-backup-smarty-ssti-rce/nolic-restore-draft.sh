#!/usr/bin/env bash
set -euo pipefail

LAB_IP="${LAB_IP:?Set LAB_IP to the current Nolic instance IP}"
SNAPSHOT="private_NOLIC_DRAFT_ID6_SNAPSHOT.json"

curl -sS -i \
  --resolve "nolic.local:80:${LAB_IP}" \
  -b nolic.cookies \
  -c nolic.cookies \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "title=$(jq -r '.title' "${SNAPSHOT}")" \
  --data-urlencode "slug=$(jq -r '.slug' "${SNAPSHOT}")" \
  --data-urlencode "excerpt=$(jq -r '.excerpt' "${SNAPSHOT}")" \
  --data-urlencode "body=$(jq -r '.body' "${SNAPSHOT}")" \
  --data-urlencode 'status=draft' \
  --data-urlencode "tags=$(jq -r '.tags' "${SNAPSHOT}")" \
  'http://nolic.local/admin/edit_post.php?id=6'
