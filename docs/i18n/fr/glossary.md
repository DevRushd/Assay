<!--
Traduction française de docs/glossary.md.

Source : docs/glossary.md
Commit source : 8ddcb44
L'anglais fait foi : en cas de désaccord, docs/glossary.md prévaut.
Cette traduction suit le texte anglais à ce commit et peut être obsolète si le
document source a changé depuis. Les termes d'état (clear, stale, undetermined,
not listed, …) restent en anglais, car ce sont les valeurs sérialisées et les
mots que le code emploie.
-->

# Glossaire : les états, et les mots qu'ils ne doivent pas confondre

Chaque bug corrigé dans ce projet était un état qui se fondait dans un autre :
`clear` tenant lieu de « non évalué », une panne rendue comme un résultat
propre, `stale` lu comme actuel, absent lu comme sûr. Les distinctions *sont*
le produit. Cette page est l'endroit unique où chaque état est défini, avec ce
qui le produit, ce qu'un consommateur doit en faire, et l'autre état avec lequel
il est le plus souvent confondu.

Lisez-la avant les autres documents. Les règles et le raisonnement vivent dans
[le modèle de sévérité](../../severity-model.md), [les vérifications](../../checks.md)
et [l'interface du contrat](../../contract-interface.md) ; cette page n'est que
le vocabulaire que ces documents supposent.

## La règle unique

**Un état, un axe, une orthographe.** Un mot nu n'est utilisé ici que s'il
nomme exactement un état. Quand deux axes réutilisent un mot — et c'est le cas
d'un (`unknown`) — l'axe est toujours nommé avec lui. `clear` n'est pas `safe` ;
absent n'est pas `clear` ; `undetermined` n'est pas absent ; `stale` n'est pas
`undetermined`.

| Ce ne sont pas des synonymes | |
| --- | --- |
| `clear` ≠ `safe` | L'émetteur n'a aucun pouvoir ; l'actif peut quand même être sans valeur ou une arnaque. |
| absent ≠ `clear` | Aucune attestation n'existe ; une attestation `clear` existe et dit « aucun pouvoir ». |
| `undetermined` ≠ absent | Une source a échoué ; « non listé » est une source qui répond qu'il n'y a pas d'entrée. |
| `stale` ≠ `undetermined` | Un verdict était complet au moment où il a été produit, puis a vieilli ; un verdict partiel n'a jamais été complet. |
| non évalué ≠ non listé | Les flags n'ont jamais été lus ; une source a été lue et n'avait pas d'entrée. |
| non listé ≠ impossible de vérifier | La liste a été lue ; la liste n'a pas pu être lue. |

## Les quatre mots vers lesquels on se tourne d'abord

### SAFE

**N'est pas un état produit par Assay.** Il n'existe pas de sévérité `safe`, de
champ `safe`, ni de valeur on-chain `safe`. Le
`is_safe(asset, max_severity, max_age_secs) == true` d'un consommateur est le
*verdict d'une gate*, calculé à partir de quatre faits : une attestation
existe, elle est assez fraîche pour cet appelant, sa sévérité est inférieure ou
égale au plafond de l'appelant, et son bitset ne touche pas le masque interdit
de l'appelant. Le verdict appartient à la politique du consommateur, pas à
Assay.

**Le plus souvent confondu avec :** `clear`. Un actif `clear` signifie que
*l'émetteur* n'a aucun pouvoir spécial sur le solde du détenteur. Cela ne
signifie pas que l'actif est authentique, solvable, ou qu'il n'est pas un rug
par un autre mécanisme. `DOGE-GA22IDJN…` ne porte aucun bit de capacité et est
une arnaque connue ([rapport d'attestation](../../attestation-run.md)).

**Action du consommateur :** ne traduisez jamais `clear`, un `evidence_hash`
concordant ou un `is_safe` admis par le mot anglais « safe » dans une UI ou un
champ d'API. La formulation honnête la plus proche est celle du modèle :
« l'émetteur n'a aucun pouvoir sur les détenteurs »
([modèle de sévérité](../../severity-model.md#what-severity-does-not-tell-you)).

### UNSAFE

**N'est pas non plus un état produit par Assay.** Les états les plus proches
sont `high` (l'émetteur peut confisquer) et `critical` (une source curatée a
identifié l'émetteur ou son domaine comme malveillant). Aucun n'est une
prédiction que l'émetteur *va* agir, et un actif `clear` peut rester dangereux
par un mécanisme qu'Assay ne scanne pas.

**Le plus souvent confondu avec :** `critical`. `critical` signifie qu'un
curateur a rendu une décision défavorable ; ce n'est pas « capacité maximale de
danger ». `DOGE` est `critical` avec une base de capacité `clear`, parce que
l'axe d'escalade et l'axe de capacité sont séparés
([modèle de sévérité](../../severity-model.md)).

**Action du consommateur :** filtrez sur l'axe qui correspond à votre
politique — le plafond de sévérité, le masque de mécaniques interdites, ou les
deux. Les deux sont nécessaires : un masque sur les bits de capacité ne voit
pas une escalade de réputation, et un plafond de sévérité ne voit pas quel
pouvoir est détenu
([intégration](../../integrating.md#2-decide-what-you-are-refusing)). La gate
d'exemple livrée sans le plafond a admis une arnaque connue sur testnet ; c'est
[#26](https://github.com/use-assay/Assay/issues/26).

### UNKNOWN

**Surchargé, donc toujours qualifié.** `unknown` est une valeur sur deux axes
différents, et un « unknown » nu est ambigu :

- **`Report.State = "unknown"`** — le verdict n'est pas utilisable : soit une
  vérification n'a pas pu conclure (`undetermined`), soit l'axe de capacité n'a
  jamais été lu (`unevaluated`). Voir
  [état du verdict](#état-du-verdict--la-réponse-est-elle-complète).
- **`Accountability = "unknown"`** — l'émetteur n'annonce pas de `home_domain`,
  donc aucune identité publiée n'existe à vérifier. C'est une constatation
  définitive, pas une incomplétude. Voir
  [responsabilité](#responsabilité--qui-porte-le-pouvoir).

Le mot nomme aussi des états sur deux autres surfaces qui ne sont *pas* le
rapport : la complétude de l'historique et des transitions
(`valid`/`unknown`/`missing`) et la comparaison de l'ensemble de vérifications
de la preuve (`unknown`/`complete`/`incomplete`). Ils sont listés sous
[le mot « unknown » ailleurs](#le-mot--unknown--ailleurs).

**Les trois choses que le langage informel appelle « unknown »** sont définies
séparément ci-dessous, car les confondre est exactement l'erreur que cette page
existe pour empêcher : [non évalué](#non-évalué), [non listé](#non-listé) et
[impossible de vérifier](#impossible-de-vérifier).

### UNDETERMINED

**Un indicateur de complétude, pas une sévérité.** `Report.Undetermined` (JSON
`"undetermined"`, avec `"undetermined_checks"` nommant les vérifications) est
vrai lorsqu'au moins une vérification n'a pas pu se terminer parce qu'une
source dont elle dépend n'a pas répondu. Il est produit par une vérification
qui enregistre une source inaccessible — un 429, un 5xx ou un timeout — et
renvoie `Finding.Undetermined = true`.

**Le plus souvent confondu avec :** `clear` / un résultat propre. Un rapport
`undetermined` porte encore ce que les vérifications qui *ont* abouti ont
établi (souvent `clear`), mais c'est un plancher, jamais une réponse : une
source en échec aurait pu cacher exactement le danger recherché. « Nous n'avons
pas pu vérifier » et « tout va bien » ne doivent jamais s'afficher de la même
façon.

**Action du consommateur :** traitez la sévérité comme un plancher, lisez
`undetermined_checks` pour voir quel axe manque, et ne vous appuyez jamais sur
l'absence d'escalade. `attest.FromReport` le refuse catégoriquement
(`ErrUndetermined`), car `get_safety` n'a nulle part où porter cette réserve ;
l'absence on-chain résultante est `None`, et chaque gate échoue fermé dessus.
Cette confusion a été corrigée dans
[#23](https://github.com/use-assay/Assay/issues/23). Le cas voisin où les flags
eux-mêmes n'ont jamais été lus est [non évalué](#non-évalué), refusé par
`ErrUnevaluated`, distinct.

## Les axes en un coup d'œil

| Axe | Champ | Valeurs | Question à laquelle il répond |
| --- | --- | --- | --- |
| Sévérité | `Report.Severity`, `Report.Base` | `clear`, `low`, `medium`, `high`, `critical` (+ `unevaluated`, Go seulement) | Que peut faire l'émetteur au solde d'un détenteur ? |
| Responsabilité | `Report.Accountability` | `unknown`, `unverified`, `verified` | Qui, s'il existe, revendique publiquement cet actif ? |
| État du verdict | `Report.State` | `valid`, `unknown`, `stale` | Cette réponse est-elle complète et actuelle ? |
| Complétude | `Report.Undetermined`, `undetermined_checks` | `true`/`false`, liste d'IDs de vérification | Toutes les sources ont-elles répondu ? |
| Stockage on-chain | `get_safety` | `None`, `Some(Safety)`, (restauration d'archives) | Une affirmation tient-elle ? |
| Source curatée | sortie de vérification + preuve | `listed`, `not listed`, `could not check` | Qu'a dit le curateur, ou qu'a-t-il omis de dire ? |

Chaque axe est indépendant. `Accountability = "verified"` n'abaisse pas
`Severity` ; `State = "stale"` ne change pas la capacité que décrivent les
flags ; une `accountability` inconnue ne rend pas le verdict `unknown`.

## Sévérité — ce que l'émetteur peut faire

La sévérité est **uniquement une capacité** et dérive des flags
d'autorisation de l'émetteur. C'est la capacité unique la plus élevée présente,
jamais une somme
([modèle de sévérité](../../severity-model.md#rule-4-do-not-double-count-what-the-protocol-requires)).
Les valeurs sont l'ABI : ne les renumérotez pas.

| Valeur | Numéro | Produite par | Action du consommateur | Le plus souvent confondue avec |
| --- | --- | --- | --- | --- |
| `clear` | 0 | vérification `capability` : aucun flag d'auth | L'émetteur n'a aucun pouvoir sur les détenteurs. Ce n'est pas un verdict de sûreté. | `unevaluated` |
| `low` | 1 | vérification `capability` : `auth_required` | L'émetteur contrôle l'entrée, pas les détenteurs existants. | `clear` (les deux « pas dangereux pour un détenteur actuel ») |
| `medium` | 2 | vérification `capability` : `auth_revocable` | L'émetteur peut geler un solde existant sur place. | `high` |
| `high` | 3 | vérification `capability` : `auth_clawback_enabled` | L'émetteur peut confisquer et brûler un solde sans signature. | `critical` |
| `critical` | 4 | vérification `reputation` : un curateur marque l'émetteur `malicious`/`unsafe`, ou bloque son domaine | Un tiers nommé a affirmé un abus. La capacité est inchangée. | `high` |
| `unevaluated` | 5 (Go seulement) | vérification `capability` quand les flags n'ont jamais été lus (`Subject.Stat == nil`) | Aucune affirmation de capacité n'existe. Jamais attesté. | `clear` |

- **`critical` est une escalade, pas une capacité.** C'est la seule valeur
  jamais produite en lisant des flags. `base_severity` et `severity` sont
  rapportés côte à côte, avec `escalated`, pour que la contribution de capacité
  reste toujours visible. Un actif `critical` sans flags se masque en ensemble
  de capacités vide.
- **`unevaluated` est délibérément hors de l'ABI on-chain.**
  `attest.FromReport` le refuse (`ErrUnevaluated`) et le contrôle de plage du
  contrat le rejetterait comme `InvalidSeverity` ; la valeur 5 n'existe que
  pour qu'un flag non lu ne puisse pas se sérialiser comme la valeur la plus
  sûre du tableau. Cette confusion a été corrigée dans
  [#32](https://github.com/use-assay/Assay/issues/32), dépendance de l'issue
  qui a produit cette page.

## Responsabilité — qui porte le pouvoir

La responsabilité est rapportée à côté de la sévérité et jamais fondue dedans
([modèle de sévérité](../../severity-model.md#rule-3-accountability-is-reported-never-discounted)).

| Valeur | Produite par | Action du consommateur | Le plus souvent confondue avec |
| --- | --- | --- | --- |
| `unknown` | `sep1-domain` : l'émetteur n'annonce aucun `home_domain` | Personne n'a publiquement revendiqué l'actif. C'est une réponse définitive. | `unverified` |
| `unverified` | `sep1-domain` : un `home_domain` existe mais la revendication réciproque a échoué ou le toml n'a pas résolu | Une revendication a été tentée et non réciproquée, ou illisible. | `unknown` |
| `verified` | `sep1-domain` : le `stellar.toml` du domaine liste exactement ce code et cet émetteur | Une partie nommée a publié une revendication. Cela ne dit rien du pouvoir ou de l'honnêteté de l'émetteur. | `safe` |

`unverified` couvre délibérément deux faits différents — « le toml n'a pas
résolu » et « il a résolu et n'a pas nommé cet actif » — parce que SEP-1 ne
permet pas à un consommateur de les distinguer à partir du seul champ ; la
distinction survit dans la preuve attribuée et le raisonnement
([rapport d'attestation](../../attestation-run.md#sep1-domain)). Cela ne
couvre **pas** « personne ne l'a revendiqué » : c'est `unknown`.

## État du verdict — la réponse est-elle complète

`Report.State` sépare une réponse utilisable d'une réponse incomplète ou
expirée. Les mêmes trois mots sont réutilisés par les vues d'historique et de
transition pour la même raison, sur leurs propres entrées.

| Valeur | Produite par | Action du consommateur | Le plus souvent confondue avec |
| --- | --- | --- | --- |
| `valid` | `Engine.Run` sur un scan complet ; évaluateur de fraîcheur dans la fenêtre | Un verdict frais et complet. Appliquez votre propre politique de sévérité/mécaniques. | `stale` |
| `unknown` | `Engine.Run` ou l'évaluateur de fraîcheur quand `Undetermined` est posé, `Base == unevaluated` ou `Severity == unevaluated` | Inutilisable. Lisez `undetermined_checks` ; n'agissez pas. | `stale` et `valid` |
| `stale` | `FreshnessEvaluator` quand l'âge du rapport dépasse la fenêtre de politique | Complet au moment où il a été produit, mais trop vieux pour agir. Vérifiez `stale_reason`. | `unknown` et `valid` |

**`stale` et `unknown` sont des échecs différents.** Un rapport `stale` était
complet quand il a été produit et est maintenant vieux ; un rapport `unknown`
n'a jamais été complet. Un rapport `unknown` ne peut jamais devenir `stale` :
la vétusté ne s'applique qu'aux verdicts qui étaient complets. Cette
distinction est [#57](https://github.com/use-assay/Assay/issues/57). Un rapport
`stale` ne peut pas être attesté (`ErrStale`), donc un verdict expiré ne peut
pas être écrit comme frais. On-chain, la gate d'exemple renvoie
`AttestationStale` (code d'erreur 2) pour la même condition, distinct de
`NotAttested` (code d'erreur 1).

## Les trois choses que « unknown » peut signifier

Ce sont les états que le langage informel fusionne le plus souvent. Ce sont
trois faits différents avec trois formes sérialisées différentes.

### Non évalué

**Orthographe :** prose « non évalué » ; sérialisé comme sévérité
`unevaluated` (5, Go seulement). **Produit par :** un `Subject` dont les flags
n'ont jamais été lus — `Stat == nil`. **Signifie :** aucune question n'a été
posée, donc aucune réponse n'existe, y compris la réponse « aucun pouvoir ».
**Action du consommateur :** il n'y a rien à attester (`ErrUnevaluated`) ;
traitez l'axe de capacité comme absent, pas comme `clear`. **Le plus souvent
confondu avec :** `clear`. Confusion corrigée dans
[#32](https://github.com/use-assay/Assay/issues/32).

### Non listé

**Orthographe :** prose « non listé » ; aucune valeur sérialisée — c'est une
*affirmation de preuve* d'une source consommée. **Produit par :** une source
curatée qui a répondu sans entrée — un HTTP 404 de StellarExpert, ou un toml qui
a résolu sans nommer l'actif. **Signifie :** la source a été lue et n'avait
rien. **Action du consommateur :** pour la réputation, c'est le cas normal et
ce n'est **pas** un signal positif : l'absence d'une liste d'arnaques n'est pas
une preuve de sûreté, et la plupart des actifs légitimes et toutes les arnaques
non signalées sont absents. **Le plus souvent confondu avec :** `undetermined`
/ impossible de vérifier. Confusion corrigée dans
[#23](https://github.com/use-assay/Assay/issues/23).

### Impossible de vérifier

**Orthographe :** prose « impossible de vérifier » ; sérialisé comme
`undetermined: true` avec `undetermined_checks`. **Produit par :** une source
qui n'a pas répondu — un 429, un 5xx ou un timeout — enregistrée comme preuve
attribuée avec l'échec verbatim. **Signifie :** la source n'a jamais été lue,
donc son absence ne porte aucune information. **Action du consommateur :**
comme pour `undetermined` ci-dessus — un plancher, pas une réponse ; non
attestable. **Le plus souvent confondu avec :** non listé, et `clear`. C'est la
confusion « Finding 1 » ([rapport d'attestation](../../attestation-run.md#finding-1)),
suivie dans [#23](https://github.com/use-assay/Assay/issues/23).

## États de stockage on-chain

Le registre stocke des attestations ; `get_safety` renvoie `Option<Safety>`.

| État | Produit par | Action du consommateur | Le plus souvent confondu avec |
| --- | --- | --- | --- |
| Jamais attesté | aucun `attest` n'a été écrit pour l'actif | Échouer fermé. Inconnu n'est pas sûr, et aucun argument ne le rend sûr. | une attestation `clear` |
| Révoqué | `revoke(asset)` a retiré l'attestation | Comme jamais attesté : aucune affirmation ne tient. Le contrat ne garde pas de pierre tombale. | jamais attesté (indistinguable pour `get_safety`) |
| Attesté | `attest(...)` a écrit un `Safety` | Appliquez `max_age_secs` contre `attested_at`, puis votre politique de sévérité et de masque. | « frais » |
| Stale (verdict de gate) | le contrôle `max_age_secs`/âge d'un consommateur | Refuser. La gate d'exemple renvoie `AttestationStale` (2), distinct de `NotAttested` (1). | jamais attesté |
| Archivé | la TTL de l'entrée a expiré | La première lecture la restaure, aux frais du lecteur, avec son `attested_at` d'origine. Elle ne se lit **pas** comme `None`. | jamais attesté / « expiré » |

- **`None` n'est pas `clear`.** Un actif jamais attesté renvoie `None` ; un
  actif clear attesté renvoie `Some(Safety{severity: 0, ...})`. Les confondre
  ferait lire chaque actif non scanné comme sûr
  ([interface du contrat](../../contract-interface.md#option-so-unknown-is-not-safe)).
- **Révoqué et jamais attesté se ressemblent on-chain, volontairement.** Les
  deux signifient « aucune affirmation ne tient » et les deux échouent fermé ;
  seul l'événement `revoke` les distingue pour un observateur off-chain
  ([interface du contrat](../../contract-interface.md#revoked-and-never-attested-look-the-same-on-chain-deliberately)).
- **L'archivage n'est pas une expiration.** Une attestation archivée est
  restaurée, pas supprimée ; ce qui protège une gate d'une ancienne, c'est
  `max_age_secs`, pas l'archive
  ([déploiement](../../deployment.md#entry-lifetime)).

## Le mot « unknown » ailleurs

Ce sont de vrais usages du mot sur des surfaces qui ne sont *pas*
`Report.State` ni la responsabilité. Ils sont listés pour qu'un lecteur ne les
preigne pas pour l'axe du rapport.

| Surface | Valeurs | Signification |
| --- | --- | --- |
| Historique (`GET /api/v1/history`) | `valid`, `unknown`, `missing` | Complétude de l'*historique* renvoyé, pas d'un scan. `missing` est « nous n'avons jamais regardé » et constitue un résultat vide explicite, jamais un 404 ni une erreur. |
| Transition (`internal/temporal`) | `valid`, `unknown`, `missing` | Si une différence a pu être dérivée entre deux observations. `missing` est moins de deux observations ; `unknown` est une entrée partielle. |
| Vérification de l'ensemble de checks (`internal/attest`) | `unknown`, `complete`, `incomplete` | Si l'ensemble de checks lié à un rapport peut être comparé à ce qu'un vérificateur attend. Pas d'ensemble lié = `unknown`, jamais `complete`. |
| Vérification de bout en bout (`docs/verifying.md`) | `valid`, `invalid`, `unknown`, `stale` | Le résultat de la *procédure* de vérification : les hashes concordent, diffèrent, n'ont pas pu être calculés, ou se vérifient mais sont anciens. Ce n'est pas un `Report.State`. |

## Exemples concrets : les confusions corrigées

- **`clear` comme « non évalué » — [#32](https://github.com/use-assay/Assay/issues/32).**
  Il n'existait aucune valeur de sévérité signifiant « jamais lu », donc un
  `Subject` vide se lisait comme `clear`, la valeur la plus sûre de l'ABI.
  Corrigé par la sentinelle `unevaluated` (5) et `ErrUnevaluated`, qui gardent
  un flag non lu hors de la préimage et hors chaîne. Voir
  [modèle de sévérité](../../severity-model.md#what-unevaluated-means).
- **Une panne comme résultat propre — [#23](https://github.com/use-assay/Assay/issues/23).**
  Un 429 de StellarExpert était ignoré, et `reputation` rapportait « c'est le
  cas normal » pour un émetteur qu'elle n'avait jamais lu. `DOGE` — une arnaque
  connue, `critical` uniquement par escalade — scannait `clear` et était
  inscriptible on-chain. Corrigé en enregistrant l'échec comme preuve
  attribuée, en posant `undetermined`, en nommant la vérification dans
  `undetermined_checks` et en refusant l'attestation. Voir
  [Finding 1](../../attestation-run.md#finding-1).
- **Stale comme actuel — [#57](https://github.com/use-assay/Assay/issues/57).**
  Un verdict complet au moment où il a été produit mais devenu trop vieux
  était indistinguable off-chain d'un verdict frais. Corrigé par
  `Report.State` (`valid`/`unknown`/`stale`) et `Report.Stale`, avec `ErrStale`
  bloquant l'attestation. Voir
  [fraîcheur](../../freshness.md#off-chain-freshness-and-report-state).
- **Un masque de capacité lu comme le verdict entier — [#26](https://github.com/use-assay/Assay/issues/26).**
  La gate d'exemple refusait les bits de capacité interdits mais ne vérifiait
  jamais le plafond de sévérité ; `DOGE`, dont la sévérité vient entièrement de
  la réputation et qui ne pose aucun bit de capacité, a donc été admis sur
  testnet. Corrigé en vérifiant les deux axes. Ce n'est pas la confusion de
  deux états Assay mais de deux questions de consommateur ; il est inclus car
  c'est la même erreur dans une gate.

## Vérifier ce glossaire contre les documents

La définition ici est celle que les autres documents affirment déjà. L'audit
qui a produit cette page a confirmé :

- [severity-model.md](../../severity-model.md) — « un actif `clear` n'est pas
  sûr », « ce que signifie unevaluated », « ce que signifie stale » : cohérents
  avec les entrées de sévérité et d'état du verdict ci-dessus.
- [checks.md](../../checks.md) — « “nous n'avons pas pu vérifier” et “tout va
  bien” ne doivent jamais s'afficher de la même façon », et la règle
  404-contre-5xx : cohérents avec
  [impossible de vérifier](#impossible-de-vérifier) et
  [non listé](#non-listé).
- [contract-interface.md](../../contract-interface.md) — `None` distinct de
  `SEVERITY_CLEAR`, révoqué/jamais attesté identiques, `unevaluated` jamais
  on-chain : cohérent avec
  [les états de stockage on-chain](#états-de-stockage-on-chain).
- [freshness.md](../../freshness.md), [history.md](../../history.md),
  [transitions.md](../../transitions.md), [verifying.md](../../verifying.md) —
  les mots réutilisés `valid`/`unknown`/`stale`/`missing` sont les énumérations
  propres à chaque surface dans
  [le mot « unknown » ailleurs](#le-mot--unknown--ailleurs), pas des définitions
  alternatives de `Report.State`.
- [attestation-run.md](../../attestation-run.md) — deux puces de « What the
  checks can get wrong » décrivaient des lacunes depuis comblées (`clear`
  tenant lieu de non évalué, et les deux copies des flags Horizon jamais
  comparées). Les deux ont été corrigées pour correspondre à ce glossaire et au
  code actuel.

## Voir aussi

- [severity-model.md](../../severity-model.md) — la couche de jugement et
  l'exception pour usage légitime.
- [checks.md](../../checks.md) — ce que chaque vérification conclut et ne peut
  pas conclure.
- [contract-interface.md](../../contract-interface.md) — l'ABI on-chain et
  l'encodage de `evidence_hash`.
- [freshness.md](../../freshness.md) — l'âge maximal d'un verdict, par classe
  d'usage.
