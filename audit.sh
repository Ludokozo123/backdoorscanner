#!/usr/bin/env bash
# HTS Security - scan read-only de TOUTES les ressources FiveM du serveur.
# Detecte automatiquement tout dossier contenant un fxmanifest.lua.

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NODE="$SCRIPT_DIR/node/bin/node"
SCANNER="$SCRIPT_DIR/index.js"
SERVER_ROOT="${1:-$(pwd)}"
SERVER_ROOT="$(cd "$SERVER_ROOT" && pwd)"
TIMEOUT_SEC=180

RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
line()   { echo -e "${CYAN}=============================================================${RESET}"; }
banner() { line; echo -e "${CYAN}${BOLD}  HTS Security - Audit anti-backdoor${RESET}"; line; }
skip()   { echo -e "${YELLOW}[HTS Security]${RESET} $1"; line; exit 0; }

banner

[ -x "$NODE" ]        || skip "Node embarque introuvable - audit ignore."
[ -f "$SCANNER" ]     || skip "Scanner introuvable - audit ignore."
[ -d "$SERVER_ROOT" ] || skip "Racine serveur invalide - audit ignore."

echo -e "${CYAN}[HTS Security]${RESET} Recherche des ressources dans $SERVER_ROOT ..."

MANIFESTS=$(find "$SERVER_ROOT" -type f -name "fxmanifest.lua" \
  -not -path "*/alpine/*" \
  -not -path "*/hts-scanner/*" \
  -not -path "*/cache/*" \
  -not -path "*/.git/*" \
  -not -path "*/node_modules/*" \
  -not -path "*/logs/*" \
  2>/dev/null)

[ -z "$MANIFESTS" ] && skip "Aucun fxmanifest.lua trouve."

TOP_DIRS=$(echo "$MANIFESTS" | while read -r m; do
  rel="${m#$SERVER_ROOT/}"
  case "$rel" in
    */*) echo "${rel%%/*}" ;;
    *)   echo "." ;;
  esac
done | sort -u)

COUNT=$(echo "$TOP_DIRS" | grep -c .)
echo -e "${CYAN}[HTS Security]${RESET} ${COUNT} dossier(s) racine detecte(s)"
echo ""

mkdir -p "$SCRIPT_DIR/reports"
rm -f "$SCRIPT_DIR/reports"/report-*.json

while read -r top; do
  [ -z "$top" ] && continue
  target="$SERVER_ROOT/$top"
  [ "$top" = "." ] && target="$SERVER_ROOT"
  echo -e "${CYAN}  -> scan $top${RESET}"
  ( cd "$SCRIPT_DIR" && timeout "$TIMEOUT_SEC" "$NODE" "$SCANNER" "$target" >/dev/null 2>&1 )
done <<< "$TOP_DIRS"

REPORTS_DIR="$SCRIPT_DIR/reports" "$NODE" <<'NODEEOF'
const fs = require('fs'), path = require('path');
const dir = process.env.REPORTS_DIR;
const files = fs.readdirSync(dir).filter(f => f.startsWith('report-') && f.endsWith('.json'));
let scanned = 0;
const seen = new Set(), issues = [];
for (const f of files) {
  try {
    const r = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf-8'));
    scanned += r.summary.scannedFiles || 0;
    for (const i of (r.issues || [])) {
      const k = (i.type||'') + '|' + (i.file||'') + '|' + (i.reason||'');
      if (!seen.has(k)) { seen.add(k); issues.push(i); }
    }
  } catch {}
}
const ORDER = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
const COLOR = { critical:'\x1b[1;31m', high:'\x1b[0;31m', medium:'\x1b[0;33m', low:'\x1b[0;36m', info:'\x1b[0;37m' };
const RESET = '\x1b[0m';
issues.sort((a,b) => (ORDER[a.risk]||9) - (ORDER[b.risk]||9));

if (issues.length === 0) {
  console.log('\x1b[0;32m[HTS Security] OK - ' + scanned + ' fichiers analyses, aucune menace detectee.\x1b[0m');
} else {
  console.log('\x1b[1;31m  ! ' + issues.length + ' MENACE(S) POTENTIELLE(S) DETECTEE(S)\x1b[0m   (' + scanned + ' fichiers analyses)');
  console.log('');
  for (const i of issues) {
    const risk = i.risk || 'info';
    console.log('  ' + (COLOR[risk]||'') + '[' + risk.toUpperCase() + ']' + RESET + ' ' + (i.reason || i.type));
    console.log('    -> ' + i.file);
  }
  console.log('');
  console.log('\x1b[0;33m  Aucun fichier n\'a ete supprime. Verifiez manuellement ces detections.\x1b[0m');
  console.log('\x1b[0;33m  Contactez votre hebergeur si vous n\'etes pas a l\'origine de ces fichiers.\x1b[0m');
}
NODEEOF

line
rm -f "$SCRIPT_DIR/reports"/report-*.json
exit 0
