# Changelog

User-facing changes are recorded here. Planned work is tracked in [the roadmap](docs/ROADMAP.md), not presented as shipped functionality.

## Unreleased

### Added
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
