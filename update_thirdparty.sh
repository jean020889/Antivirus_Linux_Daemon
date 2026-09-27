#!/bin/bash
# Script manual para descargar firmas de terceros

echo "📦 Descargando firmas de terceros para ClamAV..."
SIG_DIR="/var/lib/clamav/unofficial-sigs"
sudo mkdir -p "$SIG_DIR"

# Definir URLs de firmas (actualizadas y verificadas)
# SanSec (sanesecurity)
echo "Descargando SanSec..."
sudo wget -q -N -P "$SIG_DIR" https://sanesecurity.com/clamav/sanesecurity.ctdb.gz
sudo wget -q -N -P "$SIG_DIR" https://sanesecurity.com/clamav/sanesecurity.hdb
sudo wget -q -N -P "$SIG_DIR" https://sanesecurity.com/clamav/sanesecurity.ndb
sudo wget -q -N -P "$SIG_DIR" https://sanesecurity.com/clamav/sanesecurity.fp

# MalwarePatrol
echo "Descargando MalwarePatrol..."
sudo wget -q -N -P "$SIG_DIR" https://www.malwarepatrol.net/clamav/malwarepatrol.ndb

# SecuriteInfo
echo "Descargando SecuriteInfo..."
sudo wget -q -N -P "$SIG_DIR" https://www.securiteinfo.com/clamav/securiteinfo.hdb
sudo wget -q -N -P "$SIG_DIR" https://www.securiteinfo.com/clamav/securiteinfo.ndb

# Foxhole
echo "Descargando Foxhole..."
sudo wget -q -N -P "$SIG_DIR" https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/sigs/foxhole.ndb

# Blurl
echo "Descargando Blurl..."
sudo wget -q -N -P "$SIG_DIR" https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/sigs/blurl.ndb

# Establecer permisos correctos
sudo chown clamav:clamav "$SIG_DIR"/* 2>/dev/null || true
sudo chmod 644 "$SIG_DIR"/* 2>/dev/null || true

# Limpiar archivos vacíos
sudo find "$SIG_DIR" -type f -size 0 -delete

echo "✅ Firmas de terceros descargadas en $SIG_DIR"
echo ""
echo "📂 Archivos instalados:"
ls -la "$SIG_DIR" | grep -E "\.(hdb|ndb|ctdb|fp)$"
