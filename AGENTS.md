# collab-relay Canonical Agent Rules

## Authority

Collaboration relay brick of the Libre AI constellation, couche 4:
self-hostable transport for shared editing sessions, without depending on
a third-party service. Descends from the hub dismantling (ADR-0020) via
`git filter-repo` from `packages/collab-relay`; the hub remains the
clonable archive.
Doctrine lives upstream: https://raw.githubusercontent.com/libre-ai/governance/main/docs/README.md

## Boundaries

- Session transport is owned here; no second durable implementation of
  this domain exists elsewhere in the constellation.
- Product code and specifications for consuming applications live in their
  own repositories. Fleet doctrine and quality gates live upstream in
  `libre-ai/governance`.

## Quality gates

Run `bun run check` before pushing (Bun floor, secret scan, personal-data
scan, lint, typecheck, tests); never hide a red test.

## Agents

- Read actual state before editing.
- Stage files before running tree-walking gates (`git ls-files`-based
  scanners do not see untracked files).
- Security > quality > performance > completeness.
