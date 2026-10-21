<!--
Traducción al español de docs/integrating.md.

Fuente: docs/integrating.md
Commit de origen: 8ddcb44
El inglés es la autoridad: si hay desacuerdo, prevalece docs/integrating.md.
Esta traducción sigue el texto inglés en ese commit y puede estar desactualizada
si el documento fuente ha cambiado desde entonces. Los identificadores, comandos
y salidas se mantienen en inglés, porque son las palabras que usan el código y
las herramientas.
-->

# Llamar a `get_safety` desde su contrato

Cómo un contrato Soroban lee una atestación de Assay y se niega a actuar sobre un
activo cuyo emisor puede recuperarlo.

Todo lo de aquí se ejecuta contra el despliegue testnet live:

```
# Registro Assay en el testnet de Stellar
CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73
```

La versión completa y compilable de esta guía es
[`contracts/example-gate`](../../../assay-contracts/contracts/example-gate) — un
crate del workspace con sus tests, desplegado en testnet en
`CAL5VYSWLKG367D5IYGI57XH7EMN5PLJ4CD6K3MO2HJBYYKEKPG3NKRX` y redesplegado el
2026-09-16 con el techo de severidad
([#26](https://github.com/use-assay/Assay/issues/26)). Lea
[deployment.md](../../deployment.md) para los hashes de transacción.

## Aquello en lo que confía

Antes del código: el registro es un **almacén de atestaciones**, no un escáner.
Un contrato Soroban no puede consultar Horizon en mitad de una transacción, así
que no puede leer por sí mismo los flags de un emisor. Lo que sí puede hacer es
leer, atómicamente, lo que concluyó un escáner fuera de la cadena — la mitad que
realmente necesita estar on-chain, ya que una llamada HTTP antes de enviar puede
recibir una respuesta correspondiente a un estado del ledger distinto de aquel en
el que aterriza su transacción.

Así que confía en el atestador. Hoy eso es una sola clave. `evidence_hash` es lo
que hace que la confianza sea comprobable en lugar de absoluta: compromete
exactamente la evidencia que leyó el escáner, y cualquiera puede reescanear y
recalcularlo. La declaración completa de lo que la clave de administración puede
y no puede hacer está en [Frontera de confianza: la clave de
administración](../../contract-interface.md#trust-boundary-the-admin-key).

Para un desglose completo de cada parte en la que confía (emisor, clave del
atestador, Horizon y proveedores de reputación) y las consecuencias si cada una
es deshonesta o se equivoca, véase [trust.md](../../trust.md).

## 1. Depender del crate `assay-gate`

No necesita una dependencia del contrato de registro, pero tampoco necesita
copiar y pegar su interfaz. Las partes que llama —el tipo `Safety`, el cliente
`SafetyRegistry`, las constantes de bits de mecánicas y un asistente de
comprobación de política— se distribuyen como un pequeño crate `no_std` en este
repositorio, versionado con el ABI del registro (#469):

```toml
[dependencies]
assay-gate = { git = "https://github.com/use-assay/Assay", rev = "<revision of the registry build you target>" }
```

Fije `rev` al commit del build de registro contra el que integra —el mismo build
registrado en [deployment.md](../../deployment.md)— en lugar de a una rama. Las
constantes del crate son el ABI del registro, y el test de deriva de ABI del
motor Go analiza el crate y hace fallar el build si sus constantes dejan de
coincidir con el contrato de registro o con `internal/mechanics`, de modo que
una revisión fijada no puede renumerar un bit bajo sus pies en silencio. Luego:

```rust
use assay_gate::{Safety, SafetyRegistryClient, CAPABILITY_MASK,
    MECH_AUTH_REVOCABLE, MECH_CLAWBACK_ENABLED};
```

`Safety` cruza la frontera del contrato como un map indexado por los nombres de
sus campos, así que sus nombres y tipos son ABI — que es exactamente por lo que
viven en un único crate probado contra la deriva en lugar de en cada gate que los
copia. Lo que significa cada bit está en la tabla de abajo; `CAPABILITY_MASK`
selecciona los tres bits de poder y existe porque elegir «los bits peligrosos» a
mano es cómo ocurrió [#26](https://github.com/use-assay/Assay/issues/26).

## 2. Decidir qué está rechazando

Los bits, que son ABI y reflejan `internal/mechanics`:

| Bit | Mecánica | Qué puede hacer el emisor |
| --- | --- | --- |
| `1 << 0` | `auth_required` | Decidir quién puede abrir una trustline |
| `1 << 1` | `auth_revocable` | Congelar el saldo de un tenedor existente |
| `1 << 2` | `auth_clawback_enabled` | Confiscar y quemar un saldo |
| `1 << 3` | `auth_immutable` | Nada — el conjunto de flags nunca podrá cambiar de nuevo |
| `1 << 4` | `domain_unverified` | Nada — ninguna parte verificada reclama el activo |
| `1 << 5` | `blocklisted` | Nada — una fuente curada señaló al emisor |

La severidad `0..=4` es la misma información reducida a un único número
ordenado: `0` clear, `1` `auth_required`, `2` `auth_revocable`, `3`
`auth_clawback_enabled`, `4` escalada de reputación.

**Filtre por el bitset *y* por la severidad. Ninguno de los dos basta solo.** La
severidad responde «cuán grave es»; el bitset responde «qué poder». Fallan en
direcciones opuestas, y ambos fallos eran alcanzables con los activos atestados
a 2026-09-16:

- **La severidad sola es demasiado gruesa.** `USDC` está atestado con severidad
  `2` y flags `18` (`auth_revocable | domain_unverified`). Una gate que lea
  `severity <= 2` lo admite. Un saldo en custodia que no puede sobrevivir a una
  congelación no debería. `USDZ` muestra el mismo punto desde el otro lado:
  severidad `3`, flags `6`, y un dominio *verificado* — la verificación no
  debilita el clawback.
- **El bitset solo es ciego a la reputación.** `DOGE-GA22IDJN…` está atestado con
  severidad `4` — critical — con flags `48`
  (`domain_unverified | blocklisted`). **No lleva ningún bit de capacidad**,
  porque su emisor realmente no puede congelar ni confiscar; es critical porque
  una fuente curada lo llama malicioso. Una gate que enmascare solo
  `auth_revocable | auth_clawback_enabled` calcula `48 & 6 == 0` y **admite una
  estafa conocida.**

Ese segundo caso no era hipotético: la gate de ejemplo se publicó sin el techo y
admitía DOGE en testnet. La fuente ahora lleva el techo, con un test de regresión
que reproduce el escenario DOGE
(`critical_by_reputation_without_capability_bits_is_refused`), y la instancia
corregida se desplegó el 2026-09-16 como arreglo de
[#26](https://github.com/use-assay/Assay/issues/26). El bloque de resultados live
de abajo muestra la nueva instancia; [deployment.md](../../deployment.md) tiene
la matriz completa, incluidos los motivos de rechazo verificados para cada rama.

La razón es estructural. La escalada de reputación sube `severity` y pone
`blocklisted`; no pone un bit de capacidad, y no debe hacerlo — los bits de
capacidad describen lo que el emisor *puede hacer*, y un listado de estafa no es
una capacidad. Así que una máscara sobre los bits de capacidad no puede ver la
escalada, por diseño.

Note también que los bits `1 << 3` hasta `1 << 5` se **informan, no son
poderes** — y esa frontera ahora tiene un nombre en ambos lados en lugar de vivir
en la tabla: `CAPABILITY_MASK` (Rust, en el registro) y
`mechanics.CapabilityMask` (Go) seleccionan exactamente los tres bits de poder
`auth_required | auth_revocable | auth_clawback_enabled`, y el test de deriva de
ABI hace fallar el build si los dos lados dejan de coincidir (issue #34).
Rechazar por bits fuera de la máscara — `domain_unverified`, `blocklisted` —
rechaza la mayor parte de la red, incluidos muchos activos cuyos emisores no
pueden hacerle nada.

## 3. Escribir la gate

```rust
use assay_gate::{CAPABILITY_MASK, MECH_AUTH_REVOCABLE, MECH_CLAWBACK_ENABLED};

/// Powers a custodial balance cannot survive: the freeze and clawback bits
/// selected through the crate's exported capability mask rather than
/// hand-rolled from memory. CAPABILITY_MASK is all three power bits;
/// picking bits by hand is how #26 happened.
pub const REFUSED_MECHANICS: u32 = MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED;

/// Documented defaults for the deployed gate. These are not hidden globals;
/// they are stored in instance state at construction and are therefore visible
/// to every caller and reviewer.
pub const MAX_SEVERITY: u32 = 2;
pub const MAX_ATTESTATION_AGE: u64 = 24 * 60 * 60;

fn assert_safe(env: &Env, registry: &Address, asset: &Address) -> Result<(), Error> {
    let registry = SafetyRegistryClient::new(env, registry);

    // Handle None first and explicitly. An asset nobody has attested is
    // unknown, not safe — and treating unknown as safe would let any asset
    // through by the simple expedient of never being scanned.
    let Some(safety) = registry.get_safety(asset) else {
        return Err(Error::NotAttested);
    };

    if env.ledger().timestamp().saturating_sub(safety.attested_at) > MAX_ATTESTATION_AGE {
        return Err(Error::AttestationStale);
    }

    // Both axes, and they refuse for different reasons — so report them
    // separately. A caller that cannot tell "the issuer can take it" from
    // "a curated source calls this malicious" cannot act on either.
    if safety.severity > MAX_SEVERITY {
        return Err(Error::SeverityTooHigh);
    }

    if safety.flags & REFUSED_MECHANICS != 0 {
        return Err(Error::IssuerCanTakeIt);
    }

    Ok(())
}
```

La comprobación de severidad tiene que estar ahí aunque parezca redundante junto
a la máscara. Cada bit de capacidad tiene una severidad, así que para los activos
de la tabla de arriba la máscara parece subsumirla — hasta un activo como DOGE
cuya severidad viene de un sitio que la máscara no puede ver.

Todo el juicio de `assert_safe` —antigüedad, luego el techo, luego la máscara—
también está empaquetado en el crate como `assay_gate::check_policy`, que
devuelve cuál de los tres rechazos se aplica. La gate de ejemplo de este
repositorio lo usa (véase
[`contracts/example-gate`](../../../assay-contracts/contracts/example-gate)); la
versión explícita de arriba se queda aquí porque leer las tres comprobaciones
escritas es la forma más rápida de ver por qué ninguna es redundante.

Sobre cómo elegir `MAX_ATTESTATION_AGE`: [freshness.md](../../freshness.md) mide
con qué frecuencia cambian realmente los flags del emisor, nombra las clases de
uso que necesitan ventanas distintas y marca cada número recomendado como un
valor por defecto provisional. Léalo antes de elegir un valor — la versión corta
es que un día es defendible para una gate de depósito en custodia, que un escaneo
reciente supera a una atestación en caché para liquidaciones puntuales, y que
ninguna ventana sobrevive sin un camino de re-atestación detrás.

Luego llámela antes de actuar, en la misma transacción:

```rust
pub fn deposit(env: Env, asset: Address, from: Address, amount: i128) -> Result<(), Error> {
    from.require_auth();
    let registry: Address = env.storage().instance().get(&DataKey::Registry).unwrap();
    assert_safe(&env, &registry, &asset)?;
    // ... credit the balance
    Ok(())
}
```

### O dejar que el registro decida

Si un umbral de severidad es realmente toda su política, `is_safe` es la línea
única, y falla cerrada en todos los caminos —nunca atestado, stale, demasiado
severo o incoherente internamente:

```rust
if !registry.is_safe(&asset, &2, &3600) {
    return Err(Error::AssetNotSafe);
}
```

`max_age_secs = 0` desactiva la comprobación de frescura. Páselo solo si ha
decidido que la antigüedad es aceptable, no para que un test pase.
[freshness.md](../../freshness.md) es la guía para cualquier otro valor.

## 4. Desplegar contra el registro live

Tome la dirección del registro como argumento del constructor en lugar de
codificarla, para que el mismo wasm funcione en ambas redes:

```rust
pub fn __constructor(
    env: Env,
    registry: Address,
    max_severity: u32,
    max_age_secs: u64,
    refused_mechanics: u32,
) -> Result<(), Error> {
    if max_severity > 4 {
        return Err(Error::InvalidPolicy);
    }
    env.storage().instance().set(&DataKey::Registry, &registry);
    env.storage().instance().set(&DataKey::MaxSeverity, &max_severity);
    env.storage().instance().set(&DataKey::MaxAttestationAge, &max_age_secs);
    env.storage().instance().set(&DataKey::RefusedMechanics, &refused_mechanics);
    Ok(())
}
```

```sh
stellar contract deploy \
  --wasm target/wasm32v1-none/release/your_contract.wasm \
  --source-account your-key --network testnet \
  -- --registry CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73
```

## 5. Buscar la dirección de un activo

El registro se indexa por la **dirección del Stellar Asset Contract** de un
activo, no por `CODE:ISSUER`. La comparación de direcciones es barata on-chain;
el manejo de cadenas no lo es.

```sh
stellar contract id asset --asset AQUA:GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA \
  --network testnet
# CDJF2JQINO7WRFXB2AAHLONFDPPI4M3W2UM5THGQQ7JMJDIEJYC4CMPG
```

Esa dirección deriva de la passphrase de la red, así que **el mismo activo tiene
una dirección distinta en testnet que en pubnet**. Derívela para la red en la
que despliega; no la copie de una a otra.

## Probarlo contra el despliegue live

Tres activos atestados, y uno que deliberadamente nunca se atesta:

```sh
# Testnet deployment; every address below is network-specific.
GATE=CAL5VYSWLKG367D5IYGI57XH7EMN5PLJ4CD6K3MO2HJBYYKEKPG3NKRX

# KALE — attested clear on 2026-09-16
stellar contract invoke --id $GATE --source-account your-key --network testnet --send=no \
  -- would_admit --asset CCVNR6CGD6NFQG7XC6AVU5HF4YAPVXW5KZJCD73XFKUUO4YZUNEFKU2Z
# true

# USDZ — attested high, issuer can claw back (attestation past 24h)
stellar contract invoke --id $GATE --source-account your-key --network testnet --send=no \
  -- would_admit --asset CAOM5NKBTSGEXTZZKH3STWSFWURMODC3TZ4NS2THN7W5YUDFK3IOHIHU
# false

# native XLM — never attested
stellar contract invoke --id $GATE --source-account your-key --network testnet --send=no \
  -- would_admit --asset CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC
# false

# DOGE — attested critical (severity 4), but no capability bits
stellar contract invoke --id $GATE --source-account your-key --network testnet --send=no \
  -- would_admit --asset CDUV37BUTYKKWNGECZZNRYMM7JIQYYWAI7L2TPTXWQAEMIPG4SXRBRPD
# false — refused by the severity ceiling (#4). The pre-fix instance
#         returned true here; that was #26.
```

Cada resultado de arriba se observó contra la gate desplegada el 2026-09-16, y la
frescura los hace dependientes del tiempo: esta gate rechaza cualquier atestación
de más de 24 horas. `USDZ` se atestó por última vez en agosto, así que se rechaza
como stale (`#2`) antes de que se lea su bit de clawback — la gate comportándose
correctamente, no una regresión. `KALE`, `AQUA` y `DOGE` se atestaron o
re-atestaron el 2026-09-16, y una nueva ejecución más de un día después los verá
rechazados como stale también, a menos que alguien los re-ateste.

`DOGE` es el caso que importa. Con una atestación reciente se rechaza por el
techo de severidad — `Error(Contract, #4)`, `SeverityTooHigh` — donde la
instancia anterior al arreglo lo admitía. El registro mismo siempre respondió
correctamente (`is_safe(DOGE, 2, 0)` devolvía `false` incluso mientras la vieja
gate lo admitía), así que la culpa estaba en el ejemplo, y ahora está corregida
en la fuente, cubierta por un test de regresión y desplegada. Si copió la versión
anterior, añada el techo de severidad de la sección 3.

Enviar un `deposit` en lugar de simular le da el motivo. Verificado el
2026-09-16: el activo no atestado falla con `Error(Contract, #1)`
(`NotAttested`), `DOGE` con `#4` (`SeverityTooHigh`), y `USDZ` con `#2`
(`AttestationStale`). Una llamada fallida se rechaza en la simulación, así que no
se envía ninguna transacción; el camino admitido se ejerció con un depósito real,
registrado en [deployment.md](../../deployment.md).

## Verificar una atestación usted mismo

No tiene que aceptar la severidad almacenada por fe. `assay verify` automatiza la
comprobación reescaneando el activo, recalculando el hash, leyendo la atestación
on-chain e informando si coinciden:

```sh
$ ./assay verify USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
agreement: severity 3, flags 6, hash ca9b13a6, age 4h12m0s
```

El comando admite un flag `-max-age` (por ejemplo `-max-age=24h`) para tratar las
atestaciones stale como un fallo. Si los hashes difieren, informa del campo
concreto en desacuerdo y sale con código distinto de cero. La discrepancia
significa o bien que las fuentes del activo cambiaron desde la atestación, o bien
que la atestación no corresponde a la evidencia que afirma. El hash no puede
decirle cuál — para eso están `attested_at` y su propio reescaneo.

`assay attestation -preimage` imprime los bytes exactos que se hashean, para que
la comprobación pueda reimplementarse en cualquier lenguaje. La codificación está
especificada en [contract-interface.md](../../contract-interface.md).

Este es el esbozo de dos comandos. [verifying.md](../../verifying.md) es el
procedimiento completo: derivar la dirección para la red, leer la atestación, el
escaneo `undetermined` que hace la verificación imposible en lugar de fallida, y
la tercera causa de una discrepancia — el propio entorno del verificador, que es
[#24](https://github.com/use-assay/Assay/issues/24) y aún no está arreglado.

### O dejar que la CLI haga los tres pasos

`assay verify` (issue #39) realiza el reescaneo, el recálculo del hash y la
lectura on-chain en un solo comando, y sale con código distinto de cero ante
cualquier cosa que no sea acuerdo:

```sh
$ ./assay verify USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
AGREE: USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
on-chain attestation matches the live scan
$ echo $?
0
```

Los resultados son deliberadamente distintos — cuatro mensajes distintos y cuatro
códigos de salida distintos — porque «la atestación no coincide» y «no hay
atestación» exigen reacciones diferentes de un operador de gate:

| Resultado | Significado | Código de salida |
| --- | --- | --- |
| `agree` | escaneo, hash recalculado y cadena coinciden | 0 |
| `stale` | coinciden, pero la atestación es más antigua que `-max-age` segundos | 2 |
| `mismatch` | uno o más de `severity`, `flags`, `evidence_hash` difieren; se nombran los campos divergentes | 1 |
| `absent` | no hay atestación on-chain para este activo | 3 |
| `unverifiable` | el escaneo es undetermined (o no hay nada atestable), así que no es posible ningún veredicto | 4 |

Un escaneo undetermined **nunca** informa acuerdo: el comando se niega a comparar
una respuesta parcial con la cadena y en su lugar informa `unverifiable`. La
antigüedad solo se juzga cuando pasa `-max-age <segundos>`; sin ello, una
atestación coincidente se acepta independientemente de su edad, porque la
política de frescura pertenece al llamador (la misma política que `max_age_secs`
de `is_safe` codifica on-chain).

```sh
# fail the check when the attestation is more than an hour old
./assay verify -max-age 3600 USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR

# machine-readable verdict for scripts
./assay verify -json AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA
```

El comando lee el registro mediante la misma llamada simulada `get_safety` que
usa `make read`, así que verificar no cuesta nada y no necesita firma. El id del
registro y la red por defecto son el despliegue testnet live registrado en
[deployment.md](../../deployment.md); use `ASSAY_CONTRACT_ID` y `ASSAY_NETWORK`
para verificar contra otro despliegue.

## Indexar los eventos del registro

Un indexador es lo que nota una atestación retirada: `get_safety` devuelve `None`
tanto para nunca atestado como para revocado, y una sobrescritura reemplaza el
valor antiguo en el almacenamiento. Los eventos son el único registro de
cualquiera de los dos. Sus formas están especificadas en
[contract-interface.md](../../contract-interface.md#attestation-events); así se
consumen.

### A qué suscribirse

Filtre por el id del contrato de registro y la disposición de dos topics
`(label, asset)`:

| Evento | Topic 0 | Topic 1 | Datos (un `Map<Symbol, _>`) |
| --- | --- | --- | --- |
| attest (uno por `attest`, y uno por elemento de `attest_many`, en orden del lote) | `Symbol("attest")` | `Address` SAC del activo | `severity: u32`, `flags: u32`, `attested_at: u64` |
| revoke | `Symbol("revoke")` | `Address` SAC del activo | `revoked_at: u64` |

Un `revoke` es la única señal de que una atestación se retiró a propósito. El
archivado del almacenamiento **no** publica ningún evento: una atestación
archivada se restaura al acceder a ella y se lee sin cambios, así que un activo
que se ha quedado callado no es un activo revocado. Trate un activo como
revocado solo después de ver su evento `revoke`, y como atestado actualmente solo
si su último evento es un `attest`. Las llamadas rechazadas no publican nada, así
que cada evento que ve es una escritura que ocurrió.

### Una petición `getEvents` concreta

Los filtros de topics toman `ScVal` XDR en base64, y `*` coincide con cualquier
topic único. Los valores reales: `Symbol("attest")` es
`AAAADwAAAAZhdHRlc3QAAA==`, `Symbol("revoke")` es
`AAAADwAAAAZyZXZva2UAAA==`, y el topic de activo de abajo es la dirección SAC
de testnet `CDJF2JQINO7WRFXB2AAHLONFDPPI4M3W2UM5THGQQ7JMJDIEJYC4CMPG` (AQUA, véase
[sección 5](#5-buscar-la-dirección-de-un-activo)). Esta petición devuelve cada
attest y revoke de ese activo en el registro testnet, a partir del ledger que
elija:

```sh
curl -s https://soroban-testnet.stellar.org -H 'content-type: application/json' -d '{
  "jsonrpc": "2.0", "id": 1, "method": "getEvents",
  "params": {
    "startLedger": 3000000,
    "filters": [{
      "type": "contract",
      "contractIds": ["CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73"],
      "topics": [["*", "AAAAEgAAAAHSXSYIa79oluHQAHW5pRvejjN21RnZnNCH0sSNBE4FwQ=="]]
    }],
    "pagination": { "limit": 200 }
  }
}'
```

El segundo topic de arriba es el XDR de una dirección de contrato (`ScVal` tipo
18, tipo de dirección 1, luego los 32 bytes crudos del id SAC). Constrúyalo para
su activo en lugar de copiarlo: `assay registry-history` hace todo el viaje de
ida y vuelta y es la implementación de referencia
(`cmd/assay/registry_history.go`).

```sh
assay registry-history AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA
```

Cada resultado tiene `ledger`, `ledgerClosedAt`, `topic[]`, `value` (el map de
datos como XDR), `txHash` y un `cursor` para devolver en `pagination.cursor` en
la página siguiente. Las páginas vuelven en orden de ledger.

### Retención: lo que no puede ver

`getEvents` se sirve desde la ventana de ledgers recientes del propio nodo RPC,
no desde la cadena para siempre. `getHealth` informa `oldestLedger`,
`latestLedger` y `ledgerRetentionWindow`; la ventana por defecto de stellar-rpc es
de 17 280 ledgers (unas 24 horas) y los proveedores alojados eligen la suya. Una
petición con `startLedger` más antiguo que `oldestLedger` se rechaza, y todo lo
anterior simplemente está ausente.

Así que un indexador que arranca tarde, o que está caído más tiempo que la
ventana, **tiene un hueco que no puede rellenar desde RPC**. Un resultado vacío
significa «ningún evento en la ventana», no «nunca atestado». Ejecute el
indexador de forma continua, persista el último ledger y cursor procesados, y
archive usted mismo los eventos si necesita un historial más largo que la ventana
de su RPC. La nota de retención del propio registro está en
[contract-interface.md](../../contract-interface.md#attestation-events).

## Antes de fiarse de esto

- Está en **testnet**, no en pubnet.
- **10 activos están atestados.** Todo lo demás devuelve `None`, que su gate debe
  tratar como «desconocido», y que —si su gate es correcta— significa que su
  contrato rechaza casi todos los activos de la red.
- **Una clave puede escribir cualquier atestación.** Todavía no hay multisig ni
  umbral de atestadores independientes. La declaración completa de poderes y
  límites está en [Frontera de confianza: la clave de
  administración](../../contract-interface.md#trust-boundary-the-admin-key).
- **Nada refresca las atestaciones.** Son exactamente tan recientes como su
  `attested_at`. Elija un `max_age_secs` que realmente aceptaría.
- Testnet se reinicia periódicamente, lo que elimina estas atestaciones. Las
  entradas del registro live también se archivan (véase
  [deployment.md](../../deployment.md#entry-lifetime)). Una atestación archivada
  se restaura al leerla, con su `attested_at` original, y su transacción paga la
  tarifa de restauración. **No** se lee como `None`, así que solo `max_age_secs`
  le protege de una antigua.
