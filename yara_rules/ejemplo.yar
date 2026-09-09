rule Ejemplo_Malware {
    meta:
        description = "Detección de un string malicioso de ejemplo"
        author = "TuNombre"
    strings:
        $a = "malware"
        $b = "EjecutarComando" nocase
    condition:
        $a or $b
}
