#!/usr/bin/env bash
# Extract (CVE ID, GitHub commit URL) pairs from a local gcve-enriched-dumps checkout.
set -euo pipefail

REPO="${1:-./gcve-enriched-dumps}"
OUTPUT="${2:-patches.csv}"

command -v jq >/dev/null || { echo 'Error: jq is required.' >&2; exit 1; }
[[ -d "$REPO/cves" ]] || { echo "Error: directory not found: $REPO/cves" >&2; exit 1; }

{
  printf 'cve_id,github_patch\n'
  find "$REPO/cves" -type f -name 'CVE-*.json' -exec jq -r '
    .cveMetadata.cveId as $cve
    | [ .containers.cna.references[]?.url,
        .containers.adp[]?.references[]?.url ]
    | unique[]
    | select(type == "string" and
             test("^https?://github\\.com/[^/]+/[^/]+/commit/[0-9a-fA-F]{7,40}([/?#]|$)"))
    | [$cve, .] | @csv
  ' {} +
} > "$OUTPUT"

echo "Wrote $OUTPUT" >&2
