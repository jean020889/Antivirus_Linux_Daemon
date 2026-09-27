# Benchmarks de ScannerEngine

Métricas medidas el 2026-09-27 sobre el hardware de desarrollo
(AMD Ryzen, SSD NVMe, Linux 6.x, Python 3.12).

## Metodología

- Cada medición se repite 5 veces; se reporta la **mediana** (robusta a outliers).
- Los archivos se generan con contenido aleatorio + contador para evitar
  colisiones de hash o caching del sistema operativo.
- Los tests no verifican umbrales absolutos (frágiles en máquinas distintas);
  solo reportan números para decisión de diseño.

## Resultados

### Paralelismo con archivos grandes (20 × 1 MB)

| Configuración | Mediana | Throughput |
|---------------|---------|------------|
| Secuencial (1 hilo) | 59.06 ms | 338 files/s |
| 4 hilos | 29.31 ms | 682 files/s |
| **Speedup** | **2.01x** | |

Conclusión: `hashlib` libera el GIL durante el hashing de archivos grandes.
El paralelismo es real y útil.

### Escalado por workers (12 × 4 MB)

| Workers | Tiempo | Speedup |
|---------|--------|---------|
| 1 | 136.25 ms | 1.00x |
| 2 | 75.07 ms | 1.82x |
| 4 | 55.38 ms | **2.46x** |

Conclusión: el speedup satura alrededor de 4 workers en este hardware. Más
allá, el I/O del disco y la contención del scheduler anulan las ganancias.

### Impacto de ThreadSafeProxy (12 × 4 MB, 4 hilos)

| Configuración | Tiempo | Overhead |
|---------------|--------|----------|
| Sin proxy | 57.71 ms | — |
| Con proxy | 146.85 ms | **+154.5%** |

Conclusión: el proxy serializa todas las llamadas al engine, anulando el
paralelismo. El resultado con proxy es peor que ejecutar en 1 solo hilo.
**Por eso ScannerEngine NO usa ThreadSafeProxy.**

### Peor caso: muchos archivos pequeños (500 × 8 KB)

| Configuración | Tiempo | Throughput | µs/archivo |
|---------------|--------|------------|-----------|
| Secuencial | 26.57 ms | 18.818 files/s | 53.1 µs |

Conclusión: con archivos pequeños, el coste por archivo está dominado por
`os.stat` + apertura + hashing. El paralelismo no ayuda aquí (medido en
versión previa: 4 hilos fue 2.5x más lento que 1 hilo).

### ClamAV real vía ClamdPool (20 × 1 MB, 4 hilos)

| Configuración | Tiempo | Throughput |
|---------------|--------|------------|
| ClamdPool (4 workers) | 184.25 ms | 108 files/s |

Conclusión: ClamAV es ~6x más lento que el hashing en memoria, pero
detecta muchísimo más (firmas NDB, bytecode, heurística). El pool es la
forma correcta de no serializar las conexiones a clamd.

## Decisiones derivadas

1. **No envolver `ScannerEngine` en `ThreadSafeProxy`.** El engine es
   thread-safe por diseño (firmas inmutables + pool de clamd por hilo).
   El proxy solo añade overhead.

2. **`clamd_pool_size` óptimo: 4–8.** El speedup satura alrededor de 4
   workers en hardware de escritorio. En servidores con más núcleos y
   discos NVMe, 8 puede tener sentido. Ajustar según hardware.

3. **Usar clamd siempre que esté disponible.** La cobertura de ClamAV
   justifica la penalización de rendimiento.

4. **El fallback de firmas en memoria es válido para IOC propios.**
   Cuando clamd no está disponible, el hashing en memoria da >300 files/s
   con archivos de 1 MB, suficiente para escaneos programados.
