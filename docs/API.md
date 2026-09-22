# JEV Sentinel API — Phase 12

Base: `/api/v1`

OpenAPI: `/docs` (Swagger), `/redoc`, `/openapi.json`

All APIs use Pydantic request/response models — ORM objects are never exposed.

## Endpoints

### Health
- `GET /api/v1/health` → `{status, version, mode}`
- `GET /api/v1/readiness` → `{status, database}`

### Repositories
- `POST /api/v1/repositories/inspect` body `{path}` → `Repository + snapshot`

### Sessions
- `POST /api/v1/sessions` body `{repository_path, task, agent}` → `Session`
- `GET /api/v1/sessions/{id}` → `Session`
- `GET /api/v1/sessions?limit=&offset=` → `Session[]`

### Changes
- `POST /api/v1/changes/analyze` body `{repository_path, baseline}` → `{changeset, summary, diff_hash}`
- `POST /api/v1/changes/verify` body `{repository_path, task, jev_fixture}` → `{changeset, validation_results, security_findings, jev_evaluation, risk_assessment, policy_evaluation, decision, approval}`
- `GET /api/v1/changes?repository_path=` → current changeset

### Decisions
- `GET /api/v1/decisions/{id}` → `Decision`
- `POST /api/v1/decisions/{id}/approve` → `{status}`
- `POST /api/v1/decisions/{id}/reject`
- `POST /api/v1/decisions/{id}/retry`

### Approvals
- `POST /api/v1/approvals` body `{decision_id, changeset_id, reason}` → `ApprovalRequest`
- `GET /api/v1/approvals/{id}` → `ApprovalRequest`
- `POST /api/v1/approvals/{id}/approve` body `{approver}` → `ApprovalRequest`
- `POST /api/v1/approvals/{id}/reject` body `{approver, reason}` → `ApprovalRequest`
- `GET /api/v1/approvals` → `ApprovalRequest[]`

### Audit
- `GET /api/v1/audit?repository_id=&changeset_id=&event_type=&limit=&offset=` → `AuditEvent[]` (paginated, filtered)
- `GET /api/v1/audit/{event_id}` → `AuditEvent`

## Common Headers

- `X-Request-ID`: optional, auto-generated if missing, returned in response
- `X-Response-Time`: milliseconds

## Error Format

```json
{
  "error": "internal_error",
  "message": "...",
  "request_id": "..."
}
```

Validation errors: FastAPI default `422` with Pydantic details.

## Authentication (V1)

- `SENTINEL_ENV=development|testing` → no auth required (abstraction present)
- `SENTINEL_ENV=production` → `Authorization` header required (placeholder, verify token)
- Rate limiting: abstraction present, enable via middleware in `api/main.py`

## Pagination

All list endpoints: `?limit=20&offset=0` (max 200)

## Example

```bash
curl -X POST http://localhost:8000/api/v1/changes/verify \
  -H "Content-Type: application/json" \
  -d '{"repository_path": "/workspace/repo", "task": "Add logout endpoint", "jev_fixture": "high_confidence_safe"}'
```
