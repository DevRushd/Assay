<!--
Traduction française de la section « Status » de README.md.

Source : README.md, section « ## Status »
Commit source : 8ddcb44
L'anglais fait foi : en cas de désaccord, la version anglaise prévaut.
Cette traduction suit le texte anglais à ce commit. Si README.md a changé
depuis, elle est potentiellement obsolète (stale) et doit être mise à jour ou
signalée comme telle ; elle ne doit pas être lue comme l'état actuel du projet.
-->

# État du projet

Le moteur de mécaniques, l'API HTTP et la gate on-chain fonctionnent. La gate
est déployée sur le testnet, 18 actifs réels ont été scannés et 10 attestés à
partir de scans réels, et l'aller-retour — scan, attestation, `get_safety` —
est reproductible de bout en bout : revérifié le 2026-09-17, un nouveau scan a
reproduit le `evidence_hash` enregistré pour chaque actif attesté, avec les
limites consignées dans
[#24](https://github.com/use-assay/Assay/issues/24).
[docs/verifying.md](../../verifying.md) décrit la procédure qu'un tiers suit
pour vérifier l'une de ces attestations depuis zéro, y compris ce qu'une
divergence prouve et ne prouve pas. Elle commence par vérifier le scanner
lui-même à partir de sa somme de contrôle publiée et de sa provenance de
build, car un vérificateur qui compare des hashes de preuve fait autrement
confiance au binaire qu'il a téléchargé.

Quatre points sont à connaître avant de s'appuyer sur tout cela :

- **La couverture est de 10 actifs attestés.** Tout le reste du réseau renvoie
  `None`. C'est la bonne réponse — un actif que personne n'a scanné est
  inconnu, pas sûr — mais cela signifie que le registre n'est pas encore utile
  comme annuaire général, et qu'une gate correctement écrite refusera presque
  tout.
- **Une attestation n'est fraîche que jusqu'à son `attested_at`.** Rien ne les
  rafraîchit selon un calendrier. Les flags de l'émetteur peuvent changer
  après l'écriture d'une attestation : passez un `max_age_secs` que vous
  accepteriez réellement, plutôt que de supposer que quelqu'un maintient le
  registre à jour. [docs/freshness.md](../../freshness.md) mesure la fréquence
  réelle des changements de flags et recommande des fenêtres par cas d'usage.
- **C'est le testnet, pas le mainnet.** Une seule clé peut écrire n'importe
  quelle attestation, et le testnet est réinitialisé périodiquement. Les
  entrées du registre live sont archivées : elles sont restaurées à la lecture
  avec leur `attested_at` d'origine, et ne sont pas lues comme absentes
  ([docs/deployment.md](../../deployment.md#entry-lifetime)). Rien ici n'est
  prêt pour de l'argent réel.
- **La sévérité est une capacité, pas une prédiction.** Elle dit ce qu'un
  émetteur *peut* faire, jamais ce qu'il est susceptible de faire. Un
  stablecoin régulé avec clawback et une arnaque avec clawback obtiennent le
  même score, volontairement — voir
  [le modèle de sévérité](../../severity-model.md).

Les lacunes ne sont pas laissées implicites. [docs/threat-model.md](../../threat-model.md)
nomme les acteurs, indique quelles attaques sont défendues (avec le test qui
les maintient), quels risques sont acceptés et ce qui est hors périmètre — y
compris le plus important : une seule clé d'attesteur compromise peut
actuellement provoquer une admission.
