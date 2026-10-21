<!--
Traduction française de docs/integrating.md.

Source : docs/integrating.md
Commit source : 8ddcb44
L'anglais fait foi : en cas de désaccord, docs/integrating.md prévaut.
Cette traduction suit le texte anglais à ce commit et peut être obsolète si le
document source a changé depuis. Les identifiants, commandes et sorties restent
en anglais, car ce sont les mots que le code et les outils emploient.
-->

# Appeler `get_safety` depuis votre contrat

Comment un contrat Soroban lit une attestation Assay et refuse d'agir sur un
actif dont l'émetteur peut le reprendre.

Tout ce qui suit s'exécute contre le déploiement testnet live :

```
# Registre Assay sur le testnet Stellar
CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73
```

La version complète et compilable de ce guide est
[`contracts/example-gate`](../../../assay-contracts/contracts/example-gate) — un
crate du workspace avec ses tests, déployé sur le testnet à l'adresse
`CAL5VYSWLKG367D5IYGI57XH7EMN5PLJ4CD6K3MO2HJBYYKEKPG3NKRX` et redéployé le
2026-09-16 avec le plafond de sévérité
([#26](https://github.com/use-assay/Assay/issues/26)). Lisez
[deployment.md](../../deployment.md) pour les hashes de transaction.

## Ce à quoi vous faites confiance

Avant le code : le registre est un **magasin d'attestations**, pas un scanner.
Un contrat Soroban ne peut pas interroger Horizon au milieu d'une transaction,
donc il ne peut pas lire lui-même les flags d'un émetteur. Ce qu'il peut faire,
c'est lire atomiquement ce qu'un scanner hors chaîne a conclu — la moitié qui
doit réellement être on-chain, puisqu'un appel HTTP avant la soumission peut
recevoir une réponse correspondant à un état de registre différent de celui dans
lequel votre transaction atterrit.

Vous faites donc confiance à l'attestateur. Aujourd'hui, c'est une seule clé.
`evidence_hash` est ce qui rend cette confiance vérifiable plutôt qu'absolue :
il engage exactement la preuve que le scanner a lue, et quiconque peut rescanner
et le recalculer. L'énoncé complet de ce que la clé d'administration peut et ne
peut pas faire se trouve dans [Frontière de confiance : la clé
d'administration](../../contract-interface.md#trust-boundary-the-admin-key).

Pour le détail de chaque partie à laquelle vous faites confiance (émetteur, clé
d'attestateur, Horizon et fournisseurs de réputation) et les conséquences si
chacune est malhonnête ou se trompe, voir [trust.md](../../trust.md).

## 1. Dépendre du crate `assay-gate`

Vous n'avez pas besoin d'une dépendance au contrat de registre, mais vous n'avez
pas non plus besoin de copier-coller son interface. Les parties que vous appelez
— le type `Safety`, le client `SafetyRegistry`, les constantes de bits de
mécaniques et un assistant de vérification de politique — sont livrées comme un
petit crate `no_std` dans ce dépôt, versionné avec l'ABI du registre (#469) :

```toml
[dependencies]
assay-gate = { git = "https://github.com/use-assay/Assay", rev = "<revision of the registry build you target>" }
```

Épinglez `rev` sur le commit du build de registre contre lequel vous intégrez —
le même build que celui enregistré dans [deployment.md](../../deployment.md) —
plutôt que sur une branche. Les constantes du crate sont l'ABI du registre, et le
test de dérive d'ABI du moteur Go analyse le crate et fait échouer le build si
ses constantes cessent de concorder avec le contrat de registre ou avec
`internal/mechanics`, si bien qu'une révision épinglée ne peut pas renuméroter un
bit sous vos pieds en silence. Ensuite :

```rust
use assay_gate::{Safety, SafetyRegistryClient, CAPABILITY_MASK,
    MECH_AUTH_REVOCABLE, MECH_CLAWBACK_ENABLED};
```

`Safety` traverse la frontière du contrat sous forme de map indexée par les noms
de ses champs, donc ses noms et ses types sont l'ABI — c'est précisément
pourquoi ils vivent dans un seul crate testé contre la dérive plutôt que dans
chaque gate qui les recopie. Ce que signifie chaque bit est dans le tableau
ci-dessous ; `CAPABILITY_MASK` sélectionne les trois bits de pouvoir et existe
parce que choisir « les bits dangereux » à la main est précisément la façon dont
[#26](https://github.com/use-assay/Assay/issues/26) est arrivé.

## 2. Décider ce que vous refusez

Les bits, qui sont l'ABI et reflètent `internal/mechanics` :

| Bit | Mécanique | Ce que l'émetteur peut faire |
| --- | --- | --- |
| `1 << 0` | `auth_required` | Décider qui peut ouvrir une trustline |
| `1 << 1` | `auth_revocable` | Geler le solde d'un détenteur existant |
| `1 << 2` | `auth_clawback_enabled` | Confisquer et brûler un solde |
| `1 << 3` | `auth_immutable` | Rien — l'ensemble de flags ne pourra plus jamais changer |
| `1 << 4` | `domain_unverified` | Rien — aucune partie vérifiée ne revendique l'actif |
| `1 << 5` | `blocklisted` | Rien — une source curatée a signalé l'émetteur |

La sévérité `0..=4` est la même information réduite à un seul nombre ordonné :
`0` clear, `1` `auth_required`, `2` `auth_revocable`, `3`
`auth_clawback_enabled`, `4` escalade de réputation.

**Filtrez sur le bitset *et* sur la sévérité. Aucun des deux ne suffit seul.**
La sévérité répond à « à quel point c'est grave » ; le bitset répond à « quel
pouvoir ». Ils échouent dans des directions opposées, et les deux échecs
étaient atteignables avec les actifs attestés au 2026-09-16 :

- **La sévérité seule est trop grossière.** `USDC` est attesté à la sévérité `2`
  avec les flags `18` (`auth_revocable | domain_unverified`). Une gate lisant
  `severity <= 2` l'admet. Un solde en garde qui ne peut pas survivre à un gel
  ne devrait pas. `USDZ` montre le même point sous l'autre angle : sévérité `3`,
  flags `6`, et un domaine *vérifié* — la vérification n'affaiblit pas le
  clawback.
- **Le bitset seul est aveugle à la réputation.** `DOGE-GA22IDJN…` est attesté à
  la sévérité `4` — critical — avec les flags `48`
  (`domain_unverified | blocklisted`). Il ne porte **aucun bit de capacité**,
  parce que son émetteur ne peut réellement ni geler ni confisquer ; il est
  critical parce qu'une source curatée le qualifie de malveillant. Une gate qui
  ne masque que sur `auth_revocable | auth_clawback_enabled` calcule
  `48 & 6 == 0` et **admet une arnaque connue.**

Ce second cas n'était pas hypothétique : la gate d'exemple a été livrée sans le
plafond et admettait DOGE sur le testnet. La source porte désormais le plafond,
avec un test de régression reproduisant le scénario DOGE
(`critical_by_reputation_without_capability_bits_is_refused`), et l'instance
corrigée a été déployée le 2026-09-16 comme correctif de
[#26](https://github.com/use-assay/Assay/issues/26). Le bloc de résultats live
ci-dessous montre la nouvelle instance ; [deployment.md](../../deployment.md)
contient la matrice complète, y compris les motifs de refus vérifiés pour chaque
branche.

La raison est structurelle. L'escalade de réputation augmente `severity` et pose
`blocklisted` ; elle ne pose pas de bit de capacité, et elle ne doit pas le
faire — les bits de capacité décrivent ce que l'émetteur *peut faire*, et un
signalement d'arnaque n'est pas une capacité. Un masque sur les bits de
capacité ne peut donc pas voir l'escalade, par conception.

Notez aussi que les bits `1 << 3` à `1 << 5` sont **rapportés, pas des
pouvoirs** — et que cette frontière a désormais un nom des deux côtés au lieu de
vivre dans le tableau : `CAPABILITY_MASK` (Rust, dans le registre) et
`mechanics.CapabilityMask` (Go) sélectionnent exactement les trois bits de
pouvoir `auth_required | auth_revocable | auth_clawback_enabled`, et le test de
dérive d'ABI fait échouer le build si les deux côtés cessent de concorder
(issue #34). Refuser sur des bits hors du masque — `domain_unverified`,
`blocklisted` — refuse la majeure partie du réseau, y compris quantité d'actifs
dont les émetteurs ne peuvent rien vous faire.

## 3. Écrire la gate

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

La vérification de sévérité doit être là même si elle semble redondante à côté
du masque. Chaque bit de capacité a bien une sévérité, donc pour les actifs du
tableau ci-dessus le masque paraît la subsumer — jusqu'à un actif comme DOGE
dont la sévérité vient d'un endroit que le masque ne peut pas voir.

Le jugement complet d'`assert_safe` — vétusté, puis plafond, puis masque — est
aussi empaqueté dans le crate sous `assay_gate::check_policy`, qui renvoie
lequel des trois refus s'applique. La gate d'exemple de ce dépôt l'utilise (voir
[`contracts/example-gate`](../../../assay-contracts/contracts/example-gate)) ;
la version explicite ci-dessus reste ici parce que lire les trois vérifications
énoncées est le moyen le plus rapide de voir pourquoi aucune n'est redondante.

Sur le choix de `MAX_ATTESTATION_AGE` : [freshness.md](../../freshness.md)
mesure la fréquence réelle des changements de flags d'émetteur, nomme les
classes d'usage qui ont besoin de fenêtres différentes, et marque chaque nombre
recommandé comme une valeur par défaut provisoire. Lisez-le avant de choisir une
valeur — la version courte est qu'un jour est défendable pour une gate de dépôt
en garde, qu'un scan frais bat une attestation en cache pour les règlements
ponctuels, et qu'aucune fenêtre ne survit sans un chemin de ré-attestation
derrière elle.

Puis appelez-la avant d'agir, dans la même transaction :

```rust
pub fn deposit(env: Env, asset: Address, from: Address, amount: i128) -> Result<(), Error> {
    from.require_auth();
    let registry: Address = env.storage().instance().get(&DataKey::Registry).unwrap();
    assert_safe(&env, &registry, &asset)?;
    // ... credit the balance
    Ok(())
}
```

### Ou laisser le registre décider

Si un seuil de sévérité est réellement toute votre politique, `is_safe` est la
ligne unique, et elle échoue fermé sur tous les chemins — jamais attesté,
stale, trop sévère, ou incohérent en interne :

```rust
if !registry.is_safe(&asset, &2, &3600) {
    return Err(Error::AssetNotSafe);
}
```

`max_age_secs = 0` désactive la vérification de fraîcheur. Ne le passez que si
vous avez décidé que la vétusté est acceptable, pas pour faire passer un test.
[freshness.md](../../freshness.md) est la référence pour toute autre valeur.

## 4. Déployer contre le registre live

Prenez l'adresse du registre comme argument de constructeur plutôt que de la
coder en dur, pour que le même wasm fonctionne sur les deux réseaux :

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

## 5. Trouver l'adresse d'un actif

Le registre s'indexe sur l'**adresse du Stellar Asset Contract** d'un actif, pas
sur `CODE:ISSUER`. La comparaison d'adresses est bon marché on-chain ; la
manipulation de chaînes ne l'est pas.

```sh
stellar contract id asset --asset AQUA:GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA \
  --network testnet
# CDJF2JQINO7WRFXB2AAHLONFDPPI4M3W2UM5THGQQ7JMJDIEJYC4CMPG
```

Cette adresse dérive de la passphrase du réseau, donc **le même actif a une
adresse différente sur le testnet et sur le pubnet**. Dérivez-la pour le réseau
sur lequel vous déployez ; ne la recopiez pas d'un réseau à l'autre.

## Essayer contre le déploiement live

Trois actifs attestés, et un qui n'est délibérément jamais attesté :

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

Chaque résultat ci-dessus a été observé contre la gate déployée le 2026-09-16,
et la fraîcheur les rend dépendants du temps : cette gate refuse toute
attestation de plus de 24 heures. `USDZ` a été attesté pour la dernière fois en
août, donc il est refusé comme stale (`#2`) avant même que son bit de clawback
soit lu — la gate se comporte correctement, ce n'est pas une régression. `KALE`,
`AQUA` et `DOGE` ont été attestés ou ré-attestés le 2026-09-16, et une nouvelle
exécution plus d'un jour après les verra eux aussi refusés comme stale, sauf si
quelqu'un les ré-atteste.

`DOGE` est le cas qui compte. Avec une attestation fraîche, il est refusé par le
plafond de sévérité — `Error(Contract, #4)`, `SeverityTooHigh` — là où l'instance
d'avant le correctif l'admettait. Le registre lui-même a toujours répondu
correctement (`is_safe(DOGE, 2, 0)` renvoyait `false` même pendant que l'ancienne
gate l'admettait), donc la faute était dans l'exemple ; elle est désormais
corrigée dans la source, couverte par un test de régression, et déployée. Si
vous avez copié la version précédente, ajoutez le plafond de sévérité de la
section 3.

Soumettre un `deposit` plutôt que simuler vous donne la raison. Vérifié le
2026-09-16 : l'actif non attesté échoue avec `Error(Contract, #1)`
(`NotAttested`), `DOGE` avec `#4` (`SeverityTooHigh`), et `USDZ` avec `#2`
(`AttestationStale`). Un appel en échec est rejeté à la simulation, donc aucune
transaction n'est soumise ; le chemin admis a été exercé avec un dépôt réel,
enregistré dans [deployment.md](../../deployment.md).

## Vérifier une attestation vous-même

Vous n'êtes pas obligé de croire la sévérité stockée sur parole. `assay verify`
automatise la vérification en rescannant l'actif, en recalculant le hash, en
lisant l'attestation on-chain et en rapportant s'ils concordent :

```sh
$ ./assay verify USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
agreement: severity 3, flags 6, hash ca9b13a6, age 4h12m0s
```

La commande accepte un flag `-max-age` (par exemple `-max-age=24h`) pour traiter
les attestations stale comme un échec. Si les hashes diffèrent, elle rapporte le
champ précis en désaccord et sort avec un code non nul. La divergence signifie
soit que les sources de l'actif ont changé depuis l'attestation, soit que
l'attestation ne correspond pas à la preuve qu'elle prétend. Le hash ne peut pas
vous dire laquelle — c'est à cela que servent `attested_at` et votre propre
rescan.

`assay attestation -preimage` imprime les octets exacts hachés, pour que la
vérification puisse être réimplémentée dans n'importe quel langage. L'encodage
est spécifié dans [contract-interface.md](../../contract-interface.md).

C'est l'esquisse en deux commandes. [verifying.md](../../verifying.md) est la
procédure complète : dériver l'adresse pour le réseau, lire l'attestation, le
scan `undetermined` qui rend la vérification impossible plutôt qu'échouée, et la
troisième cause d'une divergence — l'environnement du vérificateur lui-même, qui
est [#24](https://github.com/use-assay/Assay/issues/24) et n'est pas encore
corrigé.

### Ou laisser la CLI faire les trois étapes

`assay verify` (issue #39) effectue le rescan, le recalcul de hash et la lecture
on-chain en une seule commande, et sort avec un code non nul pour tout autre
résultat que l'accord :

```sh
$ ./assay verify USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
AGREE: USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
on-chain attestation matches the live scan
$ echo $?
0
```

Les résultats sont délibérément distincts — quatre messages différents et quatre
codes de sortie différents — parce que « l'attestation n'est pas d'accord » et
« il n'y a pas d'attestation » exigent des réactions différentes de la part d'un
opérateur de gate :

| Résultat | Signification | Code de sortie |
| --- | --- | --- |
| `agree` | scan, hash recalculé et chaîne concordent tous | 0 |
| `stale` | ils concordent, mais l'attestation est plus ancienne que `-max-age` secondes | 2 |
| `mismatch` | un ou plusieurs de `severity`, `flags`, `evidence_hash` diffèrent ; les champs divergents sont nommés | 1 |
| `absent` | aucune attestation on-chain pour cet actif | 3 |
| `unverifiable` | le scan est undetermined (ou rien n'est attestable), donc aucun verdict n'est possible | 4 |

Un scan undetermined ne rapporte **jamais** un accord : la commande refuse de
comparer une réponse partielle à la chaîne et rapporte `unverifiable` à la
place. La vétusté n'est jugée que lorsque vous passez `-max-age <secondes>` ;
sans cela, une attestation concordante est acceptée quel que soit son âge, car
la politique de fraîcheur appartient à l'appelant (la même politique que
`max_age_secs` d'`is_safe` encode on-chain).

```sh
# fail the check when the attestation is more than an hour old
./assay verify -max-age 3600 USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR

# machine-readable verdict for scripts
./assay verify -json AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA
```

La commande lit le registre via le même appel `get_safety` simulé que `make
read`, donc la vérification ne coûte rien et ne nécessite pas de signature.
L'id du registre et le réseau par défaut sont le déploiement testnet live
enregistré dans [deployment.md](../../deployment.md) ; utilisez
`ASSAY_CONTRACT_ID` et `ASSAY_NETWORK` pour vérifier contre un autre
déploiement.

## Indexer les événements du registre

Un indexeur est ce qui remarque une attestation retirée : `get_safety` renvoie
`None` à la fois pour jamais attesté et pour révoqué, et une réécriture remplace
l'ancienne valeur dans le stockage. Les événements sont la seule trace des deux.
Leurs formes sont spécifiées dans
[contract-interface.md](../../contract-interface.md#attestation-events) ; voici
comment les consommer.

### À quoi s'abonner

Filtrez sur l'id du contrat de registre et la disposition à deux topics
`(label, asset)` :

| Événement | Topic 0 | Topic 1 | Données (une `Map<Symbol, _>`) |
| --- | --- | --- | --- |
| attest (un par `attest`, et un par élément de `attest_many`, dans l'ordre du lot) | `Symbol("attest")` | `Address` SAC de l'actif | `severity: u32`, `flags: u32`, `attested_at: u64` |
| revoke | `Symbol("revoke")` | `Address` SAC de l'actif | `revoked_at: u64` |

Un `revoke` est le seul signal qu'une attestation a été retirée volontairement.
L'archivage du stockage ne publie **aucun** événement : une attestation archivée
est restaurée à l'accès et se relit inchangée, donc un actif devenu silencieux
n'est pas un actif révoqué. Ne traitez un actif comme révoqué qu'après avoir vu
son événement `revoke`, et comme actuellement attesté seulement si son dernier
événement est un `attest`. Les appels rejetés ne publient rien, donc chaque
événement que vous voyez est une écriture qui a eu lieu.

### Une requête `getEvents` concrète

Les filtres de topics prennent des `ScVal` XDR en base64, et `*` correspond à
n'importe quel topic unique. Les vraies valeurs : `Symbol("attest")` est
`AAAADwAAAAZhdHRlc3QAAA==`, `Symbol("revoke")` est
`AAAADwAAAAZyZXZva2UAAA==`, et le topic d'actif ci-dessous est l'adresse SAC
testnet `CDJF2JQINO7WRFXB2AAHLONFDPPI4M3W2UM5THGQQ7JMJDIEJYC4CMPG` (AQUA, voir
[section 5](#5-trouver-ladresse-dun-actif)). Cette requête renvoie chaque attest
et revoke pour cet actif sur le registre testnet, à partir du ledger que vous
choisissez :

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

Le second topic ci-dessus est le XDR d'une adresse de contrat (`ScVal` type 18,
type d'adresse 1, puis les 32 octets bruts de l'id SAC). Construisez-le pour
votre actif plutôt que de le copier : `assay registry-history` fait tout
l'aller-retour et est l'implémentation de référence
(`cmd/assay/registry_history.go`).

```sh
assay registry-history AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA
```

Chaque résultat a `ledger`, `ledgerClosedAt`, `topic[]`, `value` (la map de
données en XDR), `txHash` et un `cursor` à repasser dans `pagination.cursor`
pour la page suivante. Les pages reviennent dans l'ordre des ledgers.

### Rétention : ce que vous ne pouvez pas voir

`getEvents` est servi depuis la fenêtre de ledgers récents du nœud RPC
lui-même, pas depuis la chaîne pour toujours. `getHealth` rapporte
`oldestLedger`, `latestLedger` et `ledgerRetentionWindow` ; la fenêtre par
défaut de stellar-rpc est de 17 280 ledgers (environ 24 heures) et les
fournisseurs hébergés choisissent la leur. Une requête avec un `startLedger`
plus ancien que `oldestLedger` est rejetée, et tout ce qui précède est
simplement absent.

Donc un indexeur qui démarre tard, ou qui est arrêté plus longtemps que la
fenêtre, **a un trou qu'il ne peut pas combler depuis le RPC**. Un résultat vide
signifie « aucun événement dans la fenêtre », pas « jamais attesté ». Faites
tourner l'indexeur en continu, persistez le dernier ledger et curseur traités,
et archivez vous-même les événements si vous avez besoin d'un historique plus
long que la fenêtre de votre RPC. La note de rétention du registre lui-même est
dans
[contract-interface.md](../../contract-interface.md#attestation-events).

## Avant de vous y fier

- C'est sur le **testnet**, pas le pubnet.
- **10 actifs sont attestés.** Tout le reste renvoie `None`, ce que votre gate
  doit traiter comme « inconnu », et qui — si votre gate est correcte — signifie
  que votre contrat refuse presque tous les actifs du réseau.
- **Une clé peut écrire n'importe quelle attestation.** Il n'y a ni multisig ni
  seuil d'attestateurs indépendants pour l'instant. L'énoncé complet des
  pouvoirs et limites est dans [Frontière de confiance : la clé
  d'administration](../../contract-interface.md#trust-boundary-the-admin-key).
- **Rien ne rafraîchit les attestations.** Elles sont exactement aussi fraîches
  que leur `attested_at`. Choisissez un `max_age_secs` que vous accepteriez
  réellement.
- Le testnet est réinitialisé périodiquement, ce qui supprime ces attestations.
  Les entrées du registre live sont aussi archivées (voir
  [deployment.md](../../deployment.md#entry-lifetime)). Une attestation
  archivée est restaurée à la lecture, avec son `attested_at` d'origine, et
  votre transaction paie les frais de restauration. Elle ne se lit **pas**
  comme `None`, donc seul `max_age_secs` vous protège d'une ancienne.
