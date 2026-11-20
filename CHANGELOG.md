# Changelog

User-facing changes are recorded here. Planned work is tracked in [the roadmap](docs/ROADMAP.md), not presented as shipped functionality.

## Unreleased

### Fixed
- Explicitly run the dedicated runtime-read PostgreSQL tests in database CI jobs instead of excluding them through name filtering.
- Remove plaintext secret names from runtime store lookup, invalidation and notification debug logs.
- Add regression coverage ensuring missing profile passwords remain errors rather than defaults or negative-cache entries.

### Added
- Internal cooperative read-budget and typed timeout foundations, with deterministic tests; public read methods remain unchanged.
- A runtime reliability roadmap covering the 14 user requests, delivery blocks, and acceptance criteria.
- This changelog. Earlier releases are not exhaustively reconstructed here.

## 0.3.0

### Added
- Bulk runtime reads and native async read sessions.
- Default database connection timeouts and TCP connection policy.

### Limitations
- Connection settings are not an end-to-end read deadline.
- This release does not add automatic retries or connection pooling.

See the repository's GitHub releases for earlier release notes.
