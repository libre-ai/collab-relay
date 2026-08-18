# collab-relay

Collaboration relay brick of the Libre AI constellation (couche 4).

Born from the hub dismantling ([ADR-0020](https://github.com/libre-ai/governance/blob/main/docs/adr/0020-general-activation-and-hub-dismantling.md)): history carried by `git filter-repo` from `libre-ai/libre-ai`, which remains the clonable archive. Consumed as a sha-pinned GitHub git-dep.

## Verify

```sh
bun install --frozen-lockfile
bun run check
```

## État du projet

<!-- libre-ai:project-status:begin -->
<!-- Section générée depuis project.v1.yaml — ne pas éditer à la main. -->

- Situation actuelle : Née verte en γ 3.4 (ex packages/collab-relay). Construite et testée, zéro consommateur en aval à ce jour — recherche croisée sur les 34 dépôts de la flotte, 2026-08-18 — en attente d'activation.
- Maturité : usable
- Exposition : spec-published
- Confiance : medium
- Preuves vérifiées le : 2026-08-18
- Avancement : 0 % du périmètre actuellement déclaré

<!-- libre-ai:project-status:end -->

La fiche [`project.v1.yaml`](./project.v1.yaml) est l'autorité de l'état du projet ; cette section en est générée et le gate de flotte échoue si elles divergent.
