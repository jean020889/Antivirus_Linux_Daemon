/*
 * Regla de ejemplo — DEMOSTRACIÓN únicamente.
 *
 * IMPORTANTE: las reglas YARA genéricas como esta producen MUCHOS
 * falsos positivos. Para producción, descarga reglas específicas
 * de malware desde:
 *   - https://github.com/Neo23x0/signature-base
 *   - https://github.com/YARA-Rules/rules
 *
 * Esta regla solo coincide con strings muy específicos que no
 * aparecen en archivos legítimos normales.
 */
rule Ejemplo_Malware_Especifico {
    meta:
        description = "Regla de ejemplo con patrón muy específico para evitar falsos positivos"
        author = "Antivirus Linux Dragon"
        reference = "https://github.com/jean020889/Antivirus_Linux_Daemon"

    strings:
        // Patrón que solo aparece en el EICAR test file
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

        // Patrón de un C2 muy específico (ficticio para el ejemplo)
        $c2_marker = "MALWARE_C2_MARKER_DO_NOT_MATCH" ascii

    condition:
        $eicar or $c2_marker
}
