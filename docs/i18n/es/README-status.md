<!--
Traducción al español de la sección «Status» de README.md.

Fuente: README.md, sección «## Status»
Commit de origen: 8ddcb44
El inglés es la autoridad: si hay desacuerdo, prevalece la versión en inglés.
Esta traducción sigue el texto inglés en ese commit. Si README.md ha cambiado
desde entonces, puede estar desactualizada (stale) y debe actualizarse o
marcarse como tal; no debe leerse como el estado actual del proyecto.
-->

# Estado del proyecto

El motor de mecánicas, la API HTTP y la gate on-chain funcionan. La gate está
desplegada en testnet, se han escaneado 18 activos reales y se han atestado 10
a partir de escaneos reales, y el recorrido completo — escaneo, atestación,
`get_safety` — es reproducible de extremo a extremo: reverificado el
2026-09-17, un escaneo nuevo reprodujo el `evidence_hash` almacenado para cada
activo atestado, con los límites registrados en
[#24](https://github.com/use-assay/Assay/issues/24).
[docs/verifying.md](../../verifying.md) es el procedimiento que sigue un
tercero para comprobar una de esas atestaciones desde cero, incluido lo que una
discrepancia prueba y lo que no. Empieza verificando el propio escáner contra
su checksum publicado y la procedencia del build, porque un verificador que
compara hashes de evidencia está, de lo contrario, confiando en el binario que
descargó.

Hay cuatro cosas que conviene saber antes de apoyarse en cualquiera de ellas:

- **La cobertura es de 10 activos atestados.** Todo lo demás en la red devuelve
  `None`. Es la respuesta correcta — un activo que nadie ha escaneado es
  desconocido, no seguro — pero significa que el registro aún no sirve como
  búsqueda general, y que una gate bien escrita rechazará casi todo.
- **Una atestación solo es tan reciente como su `attested_at`.** Nada las
  actualiza según un calendario. Los flags del emisor pueden cambiar después de
  escribir una atestación, así que pase un `max_age_secs` que realmente
  aceptaría, en lugar de suponer que alguien mantiene el registro al día.
  [docs/freshness.md](../../freshness.md) mide la frecuencia real de los cambios
  de flags y recomienda ventanas por clase de uso.
- **Esto es testnet, no mainnet.** Una sola clave puede escribir cualquier
  atestación, y testnet se reinicia periódicamente. Las entradas del registro
  live están archivadas: se restauran al leerlas con su `attested_at` original,
  y no se leen como ausentes
  ([docs/deployment.md](../../deployment.md#entry-lifetime)). Nada de esto está
  listo para dinero real.
- **La severidad es capacidad, no predicción.** Dice lo que un emisor *puede*
  hacer, nunca lo que es probable que haga. Un stablecoin regulado con clawback
  y una estafa con clawback obtienen la misma puntuación, a propósito — véase
  [el modelo de severidad](../../severity-model.md).

Las lagunas no se dejan implícitas. [docs/threat-model.md](../../threat-model.md)
nombra a los actores, indica qué ataques se defienden (con el test que los
sostiene), qué riesgos se aceptan y qué queda fuera de alcance — incluido el
más importante: una sola clave de atestador comprometida puede provocar
actualmente una admisión.
