<!--
Traducción al español de docs/glossary.md.

Fuente: docs/glossary.md
Commit de origen: 8ddcb44
El inglés es la autoridad: si hay desacuerdo, prevalece docs/glossary.md.
Esta traducción sigue el texto inglés en ese commit y puede estar desactualizada
si el documento fuente ha cambiado desde entonces. Los términos de estado
(clear, stale, undetermined, not listed, …) se mantienen en inglés, porque son
los valores serializados y las palabras que usa el código.
-->

# Glosario: los estados y las palabras que no deben confundirse

Cada bug que este proyecto ha corregido era un estado fundiéndose con otro:
`clear` haciendo las veces de «no evaluado», una caída presentándose como un
resultado limpio, `stale` leído como actual, ausente leído como seguro. Las
distinciones *son* el producto. Esta página es el único lugar donde cada estado
se define, con lo que lo produce, lo que un consumidor debe hacer con él y el
otro estado con el que más a menudo se confunde.

Léala antes que los demás documentos. Las reglas y el razonamiento viven en
[el modelo de severidad](../../severity-model.md), [las comprobaciones](../../checks.md)
y [la interfaz del contrato](../../contract-interface.md); esta página es solo
el vocabulario que esos documentos dan por supuesto.

## La única regla

**Un estado, un eje, una grafía.** Una palabra sola solo se usa aquí si nombra
exactamente un estado. Cuando dos ejes reutilizan una palabra —y uno lo hace
(`unknown`)— el eje siempre se nombra junto a ella. `clear` no es `safe`;
ausente no es `clear`; `undetermined` no es ausente; `stale` no es
`undetermined`.

| Estos no son sinónimos | |
| --- | --- |
| `clear` ≠ `safe` | El emisor no tiene ningún poder; el activo puede seguir sin valor o ser una estafa. |
| ausente ≠ `clear` | No existe ninguna atestación; una atestación `clear` existe y dice «ningún poder». |
| `undetermined` ≠ ausente | Una fuente falló; «no listado» es una fuente que responde que no hay entrada. |
| `stale` ≠ `undetermined` | Un veredicto estaba completo cuando se emitió y envejeció; un veredicto parcial nunca se completó. |
| no evaluado ≠ no listado | Los flags nunca se leyeron; una fuente se leyó y no tenía entrada. |
| no listado ≠ no se pudo comprobar | La lista se leyó; la lista no se pudo leer. |

## Las cuatro palabras a las que uno recurre primero

### SAFE

**No es un estado que Assay produzca.** No hay una severidad `safe`, ni un campo
`safe`, ni un valor on-chain `safe`. El
`is_safe(asset, max_severity, max_age_secs) == true` de un consumidor es el
*veredicto de una gate*, calculado a partir de cuatro hechos: existe una
atestación, es lo bastante reciente para ese llamador, su severidad está en el
umbral o por debajo del techo del llamador, y su bitset no toca la máscara
prohibida del llamador. El veredicto pertenece a la política del consumidor, no
a Assay.

**Se confunde más a menudo con:** `clear`. Un activo `clear` significa que *el
emisor* no tiene ningún poder especial sobre el saldo del tenedor. No significa
que el activo sea genuino, solvente o que no sea un rug por otro mecanismo.
`DOGE-GA22IDJN…` no lleva ningún bit de capacidad y es una estafa conocida
([informe de atestación](../../attestation-run.md)).

**Acción del consumidor:** nunca traduzca `clear`, un `evidence_hash` que
coincide o un `is_safe` admitido a la palabra inglesa «safe» en una UI o en un
campo de API. La formulación honesta más cercana es la que usa el modelo: «el
emisor no tiene ningún poder sobre los tenedores»
([modelo de severidad](../../severity-model.md#what-severity-does-not-tell-you)).

### UNSAFE

**Tampoco es un estado que Assay produzca.** Los estados más cercanos son `high`
(el emisor puede confiscar) y `critical` (una fuente curada ha identificado
afirmativamente al emisor o su dominio como malicioso). Ninguno es una
predicción de que el emisor *vaya* a actuar, y un activo `clear` puede seguir
siendo inseguro por un mecanismo que Assay no escanea.

**Se confunde más a menudo con:** `critical`. `critical` significa que un
curador tomó una determinación adversa; no es «capacidad máxima de peligro».
`DOGE` es `critical` con una base de capacidad `clear`, porque el eje de
escalada y el eje de capacidad son distintos
([modelo de severidad](../../severity-model.md)).

**Acción del consumidor:** filtre por el eje del que trata su política —el techo
de severidad, la máscara de mecánicas prohibidas, o ambos. Ambos son
necesarios: una máscara sobre los bits de capacidad no puede ver una escalada
de reputación, y un techo de severidad no puede ver qué poder se tiene
([integración](../../integrating.md#2-decide-what-you-are-refusing)). La gate de
ejemplo que se publicó sin el techo admitió una estafa conocida en testnet; ese
es [#26](https://github.com/use-assay/Assay/issues/26).

### UNKNOWN

**Sobrecargada y, por tanto, siempre calificada.** `unknown` es un valor en dos
ejes distintos, y un «unknown» a secas es ambiguo:

- **`Report.State = "unknown"`** — el veredicto no es utilizable: o bien una
  comprobación no pudo concluir (`undetermined`), o bien el eje de capacidad
  nunca se leyó (`unevaluated`). Véase
  [estado del veredicto](#estado-del-veredicto--está-completa-la-respuesta).
- **`Accountability = "unknown"`** — el emisor no anuncia ningún `home_domain`,
  así que no existe una identidad publicada que verificar. Es una constatación
  definitiva, no una incompletitud. Véase
  [responsabilidad](#responsabilidad--quién-sostiene-el-poder).

La palabra también nombra estados en otras dos superficies que *no* son el
informe: la completitud del historial y de las transiciones
(`valid`/`unknown`/`missing`) y la comparación del conjunto de comprobaciones de
la evidencia (`unknown`/`complete`/`incomplete`). Se listan en
[la palabra «unknown» en otros sitios](#la-palabra-unknown-en-otros-sitios).

**Las tres cosas que el lenguaje informal llama «unknown»** se definen por
separado abajo, porque fundirlas es exactamente el error que esta página existe
para evitar: [no evaluado](#no-evaluado), [no listado](#no-listado) y
[no se pudo comprobar](#no-se-pudo-comprobar).

### UNDETERMINED

**Un indicador de completitud, no una severidad.** `Report.Undetermined` (JSON
`"undetermined"`, con `"undetermined_checks"` nombrando las comprobaciones) es
verdadero cuando al menos una comprobación no pudo completarse porque una
fuente de la que depende no respondió. Lo produce una comprobación que registra
una fuente inalcanzable —un 429, un 5xx o un timeout— y devuelve
`Finding.Undetermined = true`.

**Se confunde más a menudo con:** `clear` / un resultado limpio. Un informe
`undetermined` sigue llevando lo que las comprobaciones que *sí* se completaron
establecieron (a menudo `clear`), pero es un suelo, nunca una respuesta: una
fuente que falló podría haber ocultado exactamente el peligro que se preguntaba.
«No pudimos comprobar» y «esto está bien» nunca deben presentarse igual.

**Acción del consumidor:** trate la severidad como un suelo, lea
`undetermined_checks` para ver qué eje falta y nunca se apoye en la ausencia de
una escalada. `attest.FromReport` lo rechaza de plano (`ErrUndetermined`),
porque `get_safety` no tiene dónde llevar esa salvedad; la ausencia on-chain
resultante es `None`, y cada gate falla cerrada ante ella. Esta fusión se
corrigió en [#23](https://github.com/use-assay/Assay/issues/23). El caso vecino
en el que los propios flags nunca se leyeron es
[no evaluado](#no-evaluado), rechazado con el distinto `ErrUnevaluated`.

## Los ejes de un vistazo

| Eje | Campo | Valores | Pregunta que responde |
| --- | --- | --- | --- |
| Severidad | `Report.Severity`, `Report.Base` | `clear`, `low`, `medium`, `high`, `critical` (+ `unevaluated`, solo Go) | ¿Qué puede hacer el emisor con el saldo de un tenedor? |
| Responsabilidad | `Report.Accountability` | `unknown`, `unverified`, `verified` | ¿Quién, si alguien, reclama públicamente este activo? |
| Estado del veredicto | `Report.State` | `valid`, `unknown`, `stale` | ¿Está completa y vigente esta respuesta? |
| Completitud | `Report.Undetermined`, `undetermined_checks` | `true`/`false`, lista de IDs de comprobación | ¿Respondieron todas las fuentes? |
| Almacenamiento on-chain | `get_safety` | `None`, `Some(Safety)`, (restauración de archivos) | ¿Se sostiene una afirmación? |
| Fuente curada | salida de comprobación + evidencia | `listed`, `not listed`, `could not check` | ¿Qué dijo el curador, o qué omitió decir? |

Cada eje es independiente. `Accountability = "verified"` no baja `Severity`;
`State = "stale"` no cambia la capacidad que describen los flags; una
`accountability` desconocida no convierte el veredicto en `unknown`.

## Severidad — lo que el emisor puede hacer

La severidad es **solo capacidad** y deriva de los flags de autorización del
emisor. Es la mayor capacidad individual presente, nunca una suma
([modelo de severidad](../../severity-model.md#rule-4-do-not-double-count-what-the-protocol-requires)).
Los valores son ABI: no los renumere.

| Valor | Número | Producido por | Acción del consumidor | Se confunde más a menudo con |
| --- | --- | --- | --- | --- |
| `clear` | 0 | comprobación `capability`: ningún flag de auth | El emisor no tiene ningún poder sobre los tenedores. No es un veredicto de seguridad. | `unevaluated` |
| `low` | 1 | comprobación `capability`: `auth_required` | El emisor controla la entrada, no a los tenedores existentes. | `clear` (ambos «no peligroso para un tenedor actual») |
| `medium` | 2 | comprobación `capability`: `auth_revocable` | El emisor puede congelar un saldo existente en su sitio. | `high` |
| `high` | 3 | comprobación `capability`: `auth_clawback_enabled` | El emisor puede confiscar y quemar un saldo sin firma. | `critical` |
| `critical` | 4 | comprobación `reputation`: un curador marca al emisor como `malicious`/`unsafe`, o bloquea su dominio | Un tercero nombrado ha identificado afirmativamente un abuso. La capacidad no cambia. | `high` |
| `unevaluated` | 5 (solo Go) | comprobación `capability` cuando los flags nunca se leyeron (`Subject.Stat == nil`) | No existe ninguna afirmación de capacidad. Nunca atestado. | `clear` |

- **`critical` es escalada, no capacidad.** Es el único valor que nunca se
  produce leyendo flags. `base_severity` y `severity` se informan uno al lado
  del otro, con `escalated`, para que la contribución de capacidad siempre sea
  visible. Un activo `critical` sin flags se enmascara a un conjunto de
  capacidades vacío.
- **`unevaluated` está deliberadamente fuera del ABI on-chain.**
  `attest.FromReport` lo rechaza (`ErrUnevaluated`) y la comprobación de rango
  del contrato lo rechazaría como `InvalidSeverity`; el valor 5 existe solo para
  que un flag no leído no pueda serializarse como el valor más seguro de la
  tabla. Esta fusión se corrigió en
  [#32](https://github.com/use-assay/Assay/issues/32), dependencia del issue que
  produjo esta página.

## Responsabilidad — quién sostiene el poder

La responsabilidad se informa junto a la severidad y nunca se funde en ella
([modelo de severidad](../../severity-model.md#rule-3-accountability-is-reported-never-discounted)).

| Valor | Producido por | Acción del consumidor | Se confunde más a menudo con |
| --- | --- | --- | --- |
| `unknown` | `sep1-domain`: el emisor no anuncia ningún `home_domain` | Nadie ha reclamado públicamente el activo. Es una respuesta definitiva. | `unverified` |
| `unverified` | `sep1-domain`: existe un `home_domain` pero el reclamo recíproco falló o el toml no resolvió | Se intentó un reclamo y no fue recíproco, o no era legible. | `unknown` |
| `verified` | `sep1-domain`: el `stellar.toml` del dominio lista exactamente este código y emisor | Una parte nombrada ha publicado un reclamo. No dice nada sobre el poder u honestidad del emisor. | `safe` |

`unverified` cubre deliberadamente dos hechos distintos —«el toml no resolvió» y
«resolvió y no nombraba este activo»— porque SEP-1 no permite a un consumidor
distinguirlos solo con el campo; la distinción sobrevive en la evidencia
atribuida y el razonamiento
([informe de atestación](../../attestation-run.md#sep1-domain)). **No** cubre
«nadie lo ha reclamado»: eso es `unknown`.

## Estado del veredicto — ¿está completa la respuesta?

`Report.State` separa una respuesta utilizable de una incompleta o caducada. Las
mismas tres palabras se reutilizan en las vistas de historial y transiciones por
la misma razón, sobre sus propias entradas.

| Valor | Producido por | Acción del consumidor | Se confunde más a menudo con |
| --- | --- | --- | --- |
| `valid` | `Engine.Run` sobre un escaneo completo; evaluador de frescura dentro de la ventana | Un veredicto reciente y completo. Aplique su propia política de severidad/mecánicas. | `stale` |
| `unknown` | `Engine.Run` o el evaluador de frescura cuando `Undetermined` está puesto, `Base == unevaluated` o `Severity == unevaluated` | No utilizable. Lea `undetermined_checks`; no actúe. | `stale` y `valid` |
| `stale` | `FreshnessEvaluator` cuando la edad del informe supera la ventana de la política | Completo cuando se emitió, pero demasiado antiguo para actuar. Compruebe `stale_reason`. | `unknown` y `valid` |

**`stale` y `unknown` son fallos distintos.** Un informe `stale` estaba completo
cuando se emitió y ahora es antiguo; un informe `unknown` nunca se completó. Un
informe `unknown` nunca puede volverse `stale`: la antigüedad solo se aplica a
veredictos que estaban completos. Esta distinción es
[#57](https://github.com/use-assay/Assay/issues/57). Un informe `stale` no puede
atestarse (`ErrStale`), así que un veredicto caducado no puede escribirse como
reciente. On-chain, la gate de ejemplo devuelve `AttestationStale` (código de
error 2) para la misma condición, distinto de `NotAttested` (código de error 1).

## Las tres cosas que «unknown» puede significar

Estos son los estados que el lenguaje informal fusiona más a menudo. Son tres
hechos distintos con tres formas serializadas distintas.

### No evaluado

**Grafía:** prosa «no evaluado»; serializado como severidad `unevaluated` (5,
solo Go). **Producido por:** un `Subject` cuyos flags nunca se leyeron —
`Stat == nil`. **Significa:** no se hizo ninguna pregunta, así que no existe
ninguna respuesta, incluida la respuesta «ningún poder». **Acción del
consumidor:** no hay nada que atestar (`ErrUnevaluated`); trate el eje de
capacidad como ausente, no como `clear`. **Se confunde más a menudo con:**
`clear`. Fusión corregida en
[#32](https://github.com/use-assay/Assay/issues/32).

### No listado

**Grafía:** prosa «no listado»; ningún valor serializado —es una *afirmación de
evidencia* de una fuente consumida. **Producido por:** una fuente curada que
respondió sin entrada —un HTTP 404 de StellarExpert, o un toml que resolvió y no
nombraba el activo. **Significa:** la fuente se leyó y no tenía nada. **Acción
del consumidor:** para reputación este es el caso normal y **no** es una señal
positiva: la ausencia de una lista de estafas no es evidencia de seguridad, y la
mayoría de los activos legítimos y todas las estafas no reportadas están
ausentes. **Se confunde más a menudo con:** `undetermined` / no se pudo
comprobar. Fusión corregida en
[#23](https://github.com/use-assay/Assay/issues/23).

### No se pudo comprobar

**Grafía:** prosa «no se pudo comprobar»; serializado como `undetermined: true`
con `undetermined_checks`. **Producido por:** una fuente que no respondió —un
429, un 5xx o un timeout— registrada como evidencia atribuida con el fallo
literal. **Significa:** la fuente nunca se leyó, así que su ausencia no lleva
ninguna información. **Acción del consumidor:** como para `undetermined` arriba
—suelo, no respuesta; no atestable. **Se confunde más a menudo con:** no
listado, y `clear`. Es la fusión del Finding 1
([informe de atestación](../../attestation-run.md#finding-1)), seguida en
[#23](https://github.com/use-assay/Assay/issues/23).

## Estados de almacenamiento on-chain

El registro almacena atestaciones; `get_safety` devuelve `Option<Safety>`.

| Estado | Producido por | Acción del consumidor | Se confunde más a menudo con |
| --- | --- | --- | --- |
| Nunca atestado | no se ha escrito ningún `attest` para el activo | Fallar cerrado. Desconocido no es seguro, y ningún argumento lo vuelve seguro. | una atestación `clear` |
| Revocado | `revoke(asset)` eliminó la atestación | Igual que nunca atestado: no se sostiene ninguna afirmación. El contrato no guarda lápida. | nunca atestado (indistinguible para `get_safety`) |
| Atestado | `attest(...)` escribió un `Safety` | Aplique `max_age_secs` contra `attested_at`, luego su política de severidad y máscara. | «reciente» |
| Stale (veredicto de gate) | la comprobación `max_age_secs`/edad de un consumidor | Rechazar. La gate de ejemplo devuelve `AttestationStale` (2), distinto de `NotAttested` (1). | nunca atestado |
| Archivado | el TTL de la entrada expiró | La primera lectura lo restaura, a costa del lector, con su `attested_at` original. **No** se lee como `None`. | nunca atestado / «caducado» |

- **`None` no es `clear`.** Un activo nunca atestado devuelve `None`; un activo
  clear atestado devuelve `Some(Safety{severity: 0, ...})`. Fundirlos haría que
  cada activo no escaneado se leyera como seguro
  ([interfaz del contrato](../../contract-interface.md#option-so-unknown-is-not-safe)).
- **Revocado y nunca atestado se parecen on-chain, a propósito.** Ambos
  significan «no se sostiene ninguna afirmación» y ambos fallan cerrados; solo
  el evento `revoke` los distingue para un observador off-chain
  ([interfaz del contrato](../../contract-interface.md#revoked-and-never-attested-look-the-same-on-chain-deliberately)).
- **El archivado no es caducidad.** Una atestación archivada se restaura, no se
  elimina; lo que protege a una gate de una antigua es `max_age_secs`, no el
  archivo ([despliegue](../../deployment.md#entry-lifetime)).

## La palabra «unknown» en otros sitios

Estos son usos reales de la palabra en superficies que *no* son `Report.State`
ni la responsabilidad. Se listan para que un lector no los tome por el eje del
informe.

| Superficie | Valores | Significado |
| --- | --- | --- |
| Historial (`GET /api/v1/history`) | `valid`, `unknown`, `missing` | Completitud del *historial* devuelto, no de un escaneo. `missing` es «nunca hemos mirado» y es un resultado vacío explícito, nunca un 404 ni un error. |
| Transición (`internal/temporal`) | `valid`, `unknown`, `missing` | Si se pudo derivar una diferencia entre dos observaciones. `missing` es menos de dos observaciones; `unknown` es una entrada parcial. |
| Verificación del conjunto de comprobaciones (`internal/attest`) | `unknown`, `complete`, `incomplete` | Si el conjunto de comprobaciones vinculado a un informe puede compararse con lo que un verificador espera. Sin conjunto vinculado es `unknown`, nunca `complete`. |
| Verificación de extremo a extremo (`docs/verifying.md`) | `valid`, `invalid`, `unknown`, `stale` | El resultado del *procedimiento* de verificación: los hashes coinciden, difieren, no se pudieron calcular, o se verifican pero son antiguos. No es un `Report.State`. |

## Ejemplos concretos: las fusiones que se corrigieron

- **`clear` como «no evaluado» — [#32](https://github.com/use-assay/Assay/issues/32).**
  No había ningún valor de severidad que significara «nunca leído», así que un
  `Subject` vacío se leía como `clear`, el valor más seguro del ABI. Corregido
  con el centinela `unevaluated` (5) y `ErrUnevaluated`, que mantienen un flag
  no leído fuera de la preimagen y fuera de la cadena. Véase
  [modelo de severidad](../../severity-model.md#what-unevaluated-means).
- **Una caída como resultado limpio — [#23](https://github.com/use-assay/Assay/issues/23).**
  Un 429 de StellarExpert se descartaba, y `reputation` informaba «ese es el
  caso normal» para un emisor que nunca había leído. `DOGE` —una estafa
  conocida, `critical` solo por escalada— escaneaba `clear` y era escribible
  on-chain. Corregido registrando el fallo como evidencia atribuida, poniendo
  `undetermined`, nombrando la comprobación en `undetermined_checks` y
  rechazando la atestación. Véase
  [Finding 1](../../attestation-run.md#finding-1).
- **Stale como actual — [#57](https://github.com/use-assay/Assay/issues/57).**
  Un veredicto completo cuando se emitió pero envejecido era indistinguible
  off-chain de uno reciente. Corregido con `Report.State`
  (`valid`/`unknown`/`stale`) y `Report.Stale`, con `ErrStale` bloqueando la
  atestación. Véase
  [frescura](../../freshness.md#off-chain-freshness-and-report-state).
- **Una máscara de capacidad leída como el veredicto entero — [#26](https://github.com/use-assay/Assay/issues/26).**
  La gate de ejemplo rechazaba los bits de capacidad prohibidos pero nunca
  comprobaba el techo de severidad, así que `DOGE`, cuya severidad viene
  enteramente de la reputación y que no pone ningún bit de capacidad, fue
  admitido en testnet. Corregido comprobando ambos ejes. No es la fusión de dos
  estados de Assay sino de dos preguntas del consumidor; se incluye porque es el
  mismo error en una gate.

## Comprobar este glosario contra los documentos

La definición de aquí es la que los otros documentos ya afirman. La auditoría
que produjo esta página confirmó:

- [severity-model.md](../../severity-model.md) — «un activo `clear` no es
  seguro», «qué significa unevaluated», «qué significa stale»: todo coherente
  con las entradas de severidad y estado del veredicto de arriba.
- [checks.md](../../checks.md) — «“no pudimos comprobar” y “esto está bien”
  nunca deben presentarse igual», y la regla 404-contra-5xx: coherente con
  [no se pudo comprobar](#no-se-pudo-comprobar) y [no listado](#no-listado).
- [contract-interface.md](../../contract-interface.md) — `None` distinto de
  `SEVERITY_CLEAR`, revocado/nunca atestado idénticos, `unevaluated` nunca
  on-chain: coherente con
  [los estados de almacenamiento on-chain](#estados-de-almacenamiento-on-chain).
- [freshness.md](../../freshness.md), [history.md](../../history.md),
  [transitions.md](../../transitions.md), [verifying.md](../../verifying.md) —
  las palabras reutilizadas `valid`/`unknown`/`stale`/`missing` son las
  enumeraciones propias de cada superficie en
  [la palabra «unknown» en otros sitios](#la-palabra-unknown-en-otros-sitios),
  no definiciones alternativas de `Report.State`.
- [attestation-run.md](../../attestation-run.md) — dos viñetas de «What the
  checks can get wrong» describían lagunas ya cerradas (`clear` haciendo las
  veces de no evaluado, y las dos copias de los flags de Horizon nunca
  comparadas). Ambas se corrigieron para coincidir con este glosario y el código
  actual.

## Relacionado

- [severity-model.md](../../severity-model.md) — la capa de juicio y la
  excepción para uso legítimo.
- [checks.md](../../checks.md) — qué concluye cada comprobación y qué no puede
  concluir.
- [contract-interface.md](../../contract-interface.md) — el ABI on-chain y la
  codificación de `evidence_hash`.
- [freshness.md](../../freshness.md) — cuánto puede envejecer un veredicto, por
  clase de uso.
