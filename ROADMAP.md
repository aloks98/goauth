# Implementation Roadmap

## Timeline Overview

| Phase | Name | Duration | Dependencies |
|-------|------|----------|--------------|
| 1 | Foundation | 3-4 days | None |
| 2 | Token Service | 4-5 days | Phase 1 |
| 3 | Password & API Keys | 3-4 days | Phase 1 |
| 4 | RBAC System | 5-6 days | Phase 1 |
| 5 | Store Implementations | 5-6 days | Phase 1 |
| 6 | Middleware | 4-5 days | Phase 2, 4 |
| 7 | Rate Limiting & Cleanup | 2-3 days | Phase 1, 5 |
| 8 | Testing & Docs | 3-4 days | All |

**Total Estimated Time:** 30-37 days

**Note:** OAuth/OIDC integration uses external libraries (`golang.org/x/oauth2`, `go-oidc`). See [10-oauth-integration.md](./architecture/10-oauth-integration.md) for complete examples.

---

## Phase Summary

### Phase 1: Foundation
- Project setup and structure
- Error types
- StandardClaims and generics
- Configuration structs
- Functional options
- Store interface
- Main entry point

### Phase 2: Token Service
- JWT generation (HS256, RS256)
- JWT validation
- Refresh token generation
- Refresh token rotation
- Theft detection
- Token blacklisting
- Permission version checking

### Phase 3: Password & API Keys
- Hasher interface
- Argon2id implementation
- Bcrypt implementation
- API key format
- API key manager
- Scoped API keys

### Phase 4: RBAC System
- Config file structs
- YAML/JSON loader
- Config validation
- Permission registry
- Wildcard matching
- User permission CRUD
- Role template sync

### Phase 5: Store Implementations
- Store models
- Memory store (testing)
- SQL base implementation
- PostgreSQL store
- MySQL store
- SQLite store
- Redis store
- Auto-migrations

### Phase 6: Middleware
- Core middleware logic
- Context helpers
- net/http middleware
- Fiber middleware
- Echo middleware
- Gin middleware
- Chi middleware
- Error handling

### Phase 7: Rate Limiting & Cleanup
- Rate limiter interface
- Sliding window algorithm
- Rate limit configuration
- Background cleanup worker

### Phase 8: Testing & Docs
- Unit test coverage
- Integration tests
- Benchmark tests
- Example applications
- API documentation

---

## Parallel Work Opportunities

These phases can be worked on in parallel:

```
Phase 1 (Foundation)
    │
    ├──► Phase 2 (Token)───┐
    │                      │
    ├──► Phase 3 (Password)│
    │                      ├──► Phase 6 (Middleware)
    ├──► Phase 4 (RBAC)────┘
    │
    └──► Phase 5 (Store)───────► Phase 7 (Rate Limit)
                                       │
                                       ▼
                               Phase 8 (Testing)
```

---

## Definition of Done

Each phase is complete when:

1. ✅ All tasks implemented
2. ✅ All acceptance criteria met
3. ✅ Unit tests pass with target coverage
4. ✅ Integration tests pass (where applicable)
5. ✅ Code reviewed and linted
6. ✅ Documentation updated

---

## Quick Reference

### File Locations
- Architecture docs: `architecture/`
- Phase plans: `.claude/plans/`
- Claude Code guide: `CLAUDE.md`

### Key Commands
```bash
# Test
go test ./...

# Coverage
go test ./... -coverprofile=coverage.out

# Integration
go test ./... -tags=integration

# Lint
golangci-lint run

# Benchmark
go test ./... -bench=.
```
