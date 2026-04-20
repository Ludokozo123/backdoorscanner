#!/usr/bin/env bash
# HTS Security - scan en lecture seule de TOUTES les ressources FiveM du serveur.
# Détecte automatiquement tout dossier contenant un fxmanifest.lua.

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NODE="$SCRIPT_DIR/node/bin/node"
SCANNER="$SCRIPT_DIR/index.js"
SERVER_ROOT="${1:-$(pwd)}"
SERVER_ROOT="$(cd "$SERVER_ROOT" && pwd)"
TIMEOUT_SEC=180

# Fichiers ignorés (faux positifs connus). Séparer les noms par un espace.
WHITELIST_FILES='template.lua'

RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
line()   { echo -e "${CYAN}=============================================================${RESET}"; }
banner() { line; echo -e "${CYAN}${BOLD}  HTS Security - Audit anti-backdoor${RESET}"; line; }
skip()   { echo -e "${YELLOW}[HTS Security]${RESET} $1"; line; exit 0; }

banner

[ -x "$NODE" ]        || skip "Node embarqué introuvable — audit ignoré."
[ -f "$SCANNER" ]     || skip "Scanner introuvable — audit ignoré."
[ -d "$SERVER_ROOT" ] || skip "Racine serveur invalide — audit ignoré."

echo -e "${CYAN}[HTS Security]${RESET} Recherche des ressources dans $SERVER_ROOT ..."

MANIFESTS=$(find "$SERVER_ROOT" -type f -name "fxmanifest.lua" \
  -not -path "*/alpine/*" \
  -not -path "*/hts-scanner/*" \
  -not -path "*/cache/*" \
  -not -path "*/.git/*" \
  -not -path "*/node_modules/*" \
  -not -path "*/logs/*" \
  2>/dev/null)

[ -z "$MANIFESTS" ] && skip "Aucun fxmanifest.lua trouvé."

TOP_DIRS=$(echo "$MANIFESTS" | while read -r m; do
  rel="${m#$SERVER_ROOT/}"
  case "$rel" in
    */*) echo "${rel%%/*}" ;;
    *)   echo "." ;;
  esac
done | sort -u)

COUNT=$(echo "$TOP_DIRS" | grep -c .)
echo -e "${CYAN}[HTS Security]${RESET} ${COUNT} dossier(s) racine détecté(s)"
echo ""

mkdir -p "$SCRIPT_DIR/reports"
rm -f "$SCRIPT_DIR/reports"/report-*.json

while read -r top; do
  [ -z "$top" ] && continue
  target="$SERVER_ROOT/$top"
  [ "$top" = "." ] && target="$SERVER_ROOT"
  echo -e "${CYAN}  -> scan de $top${RESET}"
  ( cd "$SCRIPT_DIR" && timeout "$TIMEOUT_SEC" "$NODE" "$SCANNER" "$target" >/dev/null 2>&1 )
done <<< "$TOP_DIRS"

REPORTS_DIR="$SCRIPT_DIR/reports" WHITELIST="$WHITELIST_FILES" "$NODE" <<'NODEEOF'
const fs = require('fs'), path = require('path');
const dir = process.env.REPORTS_DIR;
const whitelist = new Set(
  (process.env.WHITELIST || '')
    .split(/[\s,]+/)
    .map(s => s.trim().toLowerCase())
    .filter(Boolean)
);

// Traduction ES -> FR des raisons remontees par le scanner (trie par longueur decroissante)
const TRANSLATE = {
  'Exporta acceso completo al sistema de archivos del recurso': 'Expose un accès complet au système de fichiers de la ressource',
  'Verificar si es una conexión externa legítima': 'Vérifier si c\'est une connexion externe légitime',
  'Loader ofuscado con array de enteros + XOR + eval (ejecución dinámica maliciosa)': 'Loader obfusqué avec tableau d\'entiers + XOR + eval (exécution dynamique malveillante)',
  'Uso de globalThis con clave dinámica (loader/backdoor típico)': 'Utilisation de globalThis avec clé dynamique (loader/backdoor typique)',
  'Detectado endpoint malicioso con patrón Cipher Panel (/OJJ)': 'Endpoint malveillant détecté (motif Cipher Panel /OJJ)',
  'Script fuertemente ofuscado (posible evasión de análisis)': 'Script fortement obfusqué (possible évasion d\'analyse)',
  'Archivo JS en carpeta \'citizen\' contiene patrón ofuscado sospechoso': 'Fichier JS dans le dossier \'citizen\' contient un motif obfusqué suspect',
  'Archivo JS oculto o con nombre sospechoso (empieza con .)': 'Fichier JS caché ou avec un nom suspect (commence par .)',
  'Archivo JS comienza con patrón sospechoso (/* [)': 'Fichier JS commence par un motif suspect (/* [)',
  'Archivo contiene globalThis con código ofuscado (posible backdoor)': 'Fichier contient globalThis avec code obfusqué (possible backdoor)',
  'Archivo contiene patrón ofuscado que coincide con alguna carpeta de su ruta': 'Fichier contient un motif obfusqué qui correspond à un dossier de son chemin',
  'Archivo Lua dentro de carpeta ocultada con attrib +h +s': 'Fichier Lua dans un dossier caché (attrib +h +s)',
  'Carpeta ocultada con attrib +h +s': 'Dossier caché avec attrib +h +s',
  'Descifrado XOR detectado (patrón típico de backdoors).': 'Déchiffrement XOR détecté (motif typique des backdoors).',
  'Ofuscación mediante reemplazo Unicode y ejecución dinámica.': 'Obfuscation via remplacement Unicode et exécution dynamique.',
  'Detección de función de desofuscación (posible código malicioso).': 'Fonction de déobfuscation détectée (possible code malveillant).',
  'Se encontró una IP estática.': 'IP statique trouvée.',
  'DLL nativo (no .NET). Los recursos FiveM usan .NET — este DLL es inusual. Revisión manual recomendada.': 'DLL natif (non .NET). Les ressources FiveM utilisent .NET — ce DLL est inhabituel. Révision manuelle recommandée.',
  'El archivo no tiene cabecera PE válida': 'Le fichier n\'a pas d\'en-tête PE valide',
  'Archivo .dll no encontrado en disco': 'Fichier .dll introuvable sur le disque',
  'El patrón JS no coincide con ningún archivo': 'Le motif JS ne correspond à aucun fichier',
  'FIRMA DE BACKDOOR CONOCIDO': 'SIGNATURE DE BACKDOOR CONNUE',
  'DLL con capacidades críticas': 'DLL avec capacités critiques',
  'DLL con múltiples indicadores sospechosos': 'DLL avec plusieurs indicateurs suspects',
  'Uso de función sensible': 'Utilisation de fonction sensible',
  'Detectado patrón ofuscado conocido': 'Motif obfusqué connu détecté',
  'El archivo contiene un comentario de ofuscación que coincide con la carpeta': 'Le fichier contient un commentaire d\'obfuscation qui correspond au dossier',
  'Archivo .net.dll referenciado en': 'Fichier .net.dll référencé dans',
  'archivo no encontrado en disco': 'fichier introuvable sur le disque',
  // Mots isoles (fallback pour raisons dynamiques non couvertes ci-dessus)
  'Archivo': 'Fichier', 'archivo': 'fichier',
  'Carpeta': 'Dossier', 'carpeta': 'dossier',
  'ocultada': 'caché', 'ocultado': 'caché', 'oculto': 'caché', 'oculta': 'cachée',
  'sospechoso': 'suspect', 'sospechosa': 'suspecte',
  'sospechosos': 'suspects', 'sospechosas': 'suspectes',
  'malicioso': 'malveillant', 'maliciosa': 'malveillante', 'maliciosos': 'malveillants',
  'ofuscado': 'obfusqué', 'ofuscada': 'obfusquée', 'ofuscación': 'obfuscation',
  'detectado': 'détecté', 'detectada': 'détectée', 'Detectado': 'Détecté',
  'conocido': 'connu', 'conocida': 'connue',
  'patrón': 'motif', 'patrones': 'motifs',
  'ejecución': 'exécution', 'dinámica': 'dynamique',
  'típico': 'typique', 'típica': 'typique',
  'posible': 'possible',
  'conexión': 'connexion', 'externa': 'externe', 'legítima': 'légitime',
  'capacidades': 'capacités', 'críticas': 'critiques',
  'múltiples': 'multiples', 'indicadores': 'indicateurs',
  'encontrado': 'trouvé', 'encontrada': 'trouvée',
  'comienza': 'commence', 'empieza': 'commence',
  'sensible': 'sensible', 'función': 'fonction',
  'referenciado': 'référencé',
  ' con ': ' avec ', ' en ': ' dans ', ' sin ': ' sans ',
  ' dentro de ': ' dans ',
};
const entries = Object.entries(TRANSLATE).sort((a, b) => b[0].length - a[0].length);
function fr(s) {
  if (!s) return s;
  let out = String(s);
  for (const [es, fra] of entries) out = out.split(es).join(fra);
  return out;
}

const files = fs.readdirSync(dir).filter(f => f.startsWith('report-') && f.endsWith('.json'));
let scanned = 0, skippedWL = 0;
const seen = new Set(), issues = [];
for (const f of files) {
  try {
    const r = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf-8'));
    scanned += r.summary.scannedFiles || 0;
    for (const i of (r.issues || [])) {
      const base = path.basename(i.file || '').toLowerCase();
      if (whitelist.has(base)) { skippedWL++; continue; }
      const k = (i.type||'') + '|' + (i.file||'') + '|' + (i.reason||'');
      if (!seen.has(k)) { seen.add(k); issues.push(i); }
    }
  } catch {}
}
if (skippedWL > 0) {
  console.log('\x1b[0;37m[HTS Security] ' + skippedWL + ' détection(s) ignorée(s) via la whitelist.\x1b[0m');
}
const ORDER = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
const LABEL = { critical: 'CRITIQUE', high: 'ÉLEVÉ', medium: 'MOYEN', low: 'FAIBLE', info: 'INFO' };
const COLOR = { critical:'\x1b[1;31m', high:'\x1b[0;31m', medium:'\x1b[0;33m', low:'\x1b[0;36m', info:'\x1b[0;37m' };
const RESET = '\x1b[0m';
issues.sort((a,b) => (ORDER[a.risk]||9) - (ORDER[b.risk]||9));

if (issues.length === 0) {
  console.log('\x1b[0;32m[HTS Security] OK — ' + scanned + ' fichiers analysés, aucune menace détectée.\x1b[0m');
} else {
  console.log('\x1b[1;31m  ! ' + issues.length + ' MENACE(S) POTENTIELLE(S) DÉTECTÉE(S)\x1b[0m   (' + scanned + ' fichiers analysés)');
  console.log('');
  for (const i of issues) {
    const risk = i.risk || 'info';
    const label = LABEL[risk] || risk.toUpperCase();
    console.log('  ' + (COLOR[risk]||'') + '[' + label + ']' + RESET + ' ' + fr(i.reason || i.type));
    console.log('    -> ' + i.file);
  }
  console.log('');
  console.log('\x1b[0;33m  Aucun fichier n\'a été supprimé. Vérifiez manuellement ces détections.\x1b[0m');
  console.log('\x1b[0;33m  Contactez votre hébergeur si vous n\'êtes pas à l\'origine de ces fichiers.\x1b[0m');
  console.log('');
  console.log('\x1b[1;36m  >> Besoin d\'aide ? Rejoignez notre Discord : https://discord.gg/VOTRE_INVITE\x1b[0m');
}
NODEEOF

line
rm -f "$SCRIPT_DIR/reports"/report-*.json
exit 0
