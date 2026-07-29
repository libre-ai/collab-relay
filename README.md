# collab-relay

Collaboration relay brick of the Libre AI constellation (couche 4).

Born from the hub dismantling ([ADR-0020](https://github.com/libre-ai/governance/blob/main/docs/adr/0020-general-activation-and-hub-dismantling.md)): history carried by `git filter-repo` from `libre-ai/libre-ai`, which remains the clonable archive. Consumed as a sha-pinned GitHub git-dep.

## Verify

```sh
bun install --frozen-lockfile
bun run check
```
