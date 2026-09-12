#!/usr/bin/env bash
# Phase B: vendor DPI source trees at pinned commits with provenance.
# Shallow clones (we want the data, not the history), but the exact SHA is
# recorded so any extraction is reproducible.
set -uo pipefail

TP="$(cd "$(dirname "$0")/.." && pwd)/third_party"
mkdir -p "$TP"

vendor() {
  local name="$1" url="$2" license="$3" purpose="$4"
  local dest="$TP/$name"

  if [ -d "$dest/.git" ]; then
    echo "[skip] $name already vendored"
    return 0
  fi

  echo "[clone] $name <- $url"
  if ! git clone --depth 1 --quiet "$url" "$dest" 2>&1 | tail -2; then
    echo "[FAIL] $name"
    return 1
  fi

  local sha date
  sha=$(git -C "$dest" rev-parse HEAD)
  date=$(git -C "$dest" log -1 --format=%cI)

  cat > "$dest/PROVENANCE.md" <<PROV
# Provenance: $name

- **Upstream**: $url
- **Pinned commit**: \`$sha\`
- **Commit date**: $date
- **Vendored on**: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- **License**: $license
- **Why we have it**: $purpose

This tree is a **corpus**, not a build dependency. It is read-only input to the
extractors under \`tools/extract/\`. Do not modify it; re-vendor at a new pinned
commit instead.
PROV

  for f in LICENSE LICENSE.txt LICENSE.md COPYING COPYING.txt LICENCE; do
    [ -f "$dest/$f" ] && cp "$dest/$f" "$dest/LICENSE.vendored" && break
  done

  local size
  size=$(du -sh "$dest" 2>/dev/null | cut -f1)
  echo "[ok]   $name  $sha  ($size)"
}

vendor ndpi          https://github.com/ntop/nDPI.git                     LGPL-3.0   "434 protocols; 3.2MB IP/ASN tables; utils/ generators to REGENERATE from public feeds"
vendor mmt-dpi       https://github.com/Montimage/mmt-dpi.git             Apache-2.0 "682 protocol defines; permissive C engine; 5G/LTE (GTP/NAS/NGAP)"
vendor peafowl       https://github.com/DanieleDeSensi/peafowl.git        MIT        "Permissive L7 framework; multicore reference"
vendor libprotoident https://github.com/LibtraceTeam/libprotoident.git    LGPL-3.0   "4-byte classification; legacy P2P/game coverage"
vendor netify-agent  https://gitlab.com/netify.ai/public/netify-agent.git GPL-3.0    "netify-apps.conf is Apache-2.0 DATA: 199 apps / 4183 rules"
vendor vectorscan    https://github.com/VectorCamp/vectorscan.git         BSD-3      "SIMD multi-regex; the regex tier"
vendor arkime        https://github.com/arkime/arkime.git                 Apache-2.0 "JA4 fingerprinting + metadata model"

echo
echo "=== vendored ==="
du -sh "$TP"/* 2>/dev/null | sort -rh
