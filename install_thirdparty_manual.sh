#!/bin/bash
echo "📦 Instalación manual de firmas de terceros para ClamAV..."

# Crear directorio para firmas de terceros
sudo mkdir -p /var/lib/clamav/unofficial-sigs
cd /var/lib/clamav/unofficial-sigs

# Descargar firmas de SanSec (sanesecurity)
echo "Descargando firmas SanSec..."
sudo wget -q -N https://sanesecurity.com/clamav/sanesecurity.ctdb.gz
sudo wget -q -N https://sanesecurity.com/clamav/sanesecurity.hdb
sudo wget -q -N https://sanesecurity.com/clamav/sanesecurity.ndb
sudo wget -q -N https://sanesecurity.com/clamav/sanesecurity.fp

# Descargar firmas de MalwarePatrol
echo "Descargando firmas MalwarePatrol..."
sudo wget -q -N https://www.malwarepatrol.net/clamav/malwarepatrol.ndb

# Descargar firmas de SecuriteInfo
echo "Descargando firmas SecuriteInfo..."
sudo wget -q -N https://www.securiteinfo.com/clamav/securiteinfo.hdb
sudo wget -q -N https://www.securiteinfo.com/clamav/securiteinfo.ndb

# Descargar firmas de Foxhole (opcional)
echo "Descargando firmas Foxhole..."
sudo wget -q -N https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/sigs/foxhole.ndb

# Establecer permisos
sudo chown clamav:clamav /var/lib/clamav/unofficial-sigs/*
sudo chmod 644 /var/lib/clamav/unofficial-sigs/*

echo "✅ Firmas de terceros instaladas manualmente en /var/lib/clamav/unofficial-sigs"
echo "   Para actualizarlas regularmente, ejecuta este script periódicamente."
