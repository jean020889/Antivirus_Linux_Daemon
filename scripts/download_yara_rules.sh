#!/usr/bin/env bash
# Descarga reglas YARA comunitarias para Antivirus Pro EDR.
# Uso: ./scripts/download_yara_rules.sh
set -euo pipefail

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/yara_rules"
TMP="$(mktemp -d)"
trap "rm -rf $TMP" EXIT

echo "[+] Descargando reglas YARA comunitarias..."
git clone --depth 1 https://github.com/Yara-Rules/rules "$TMP/community"

echo "[+] Copiando .yar/.yara a $DEST/"
find "$TMP/community" \( -name '*.yar' -o -name '*.yara' \) \
    -exec cp {} "$DEST/" \;

echo "[+] Descargando reglas Neo23x0..."
git clone --depth 1 https://github.com/Neo23x0/signature-base "$TMP/neo23x0"
find "$TMP/neo23x0/yara" -name '*.yar' -exec cp {} "$DEST/" \; 2>/dev/null || true

echo "[+] Total reglas: $(find "$DEST" -name '*.yar' -o -name '*.yara' | wc -l)"
echo "[+] Listo. Reinicia el daemon para recargarlas."
