# AI Coding Agent Instructions – NAVvoice

## 🎯 Mission
Build a **multi-tenant Hungarian NAV invoice reconciliation system** that detects missing invoices (NAV XML metadata vs received PDFs) and automates vendor outreach via AI-generated emails with human approval gates.

---

## 🏗️ Architecture Overview

### Core Value Stream
```
Sync invoices from NAV → Ingest PDFs → Match & detect gaps → 
Draft outreach (AI) → Approve (human) → Send email → Audit
```

### Key Modules & Responsibilities

| Module | Purpose | Pattern |
|--------|---------|---------|
| `nav_client.py` | NAV API communication (XML signatures, token exchange) | Singleton pattern; extensive error enum (retryable vs permanent) |
| `invoice_agent.py` | Gemini AI email generation with prompt injection guards | Input sanitizer → LLM → Output validator |
| `approval_queue.py` | Human-in-the-loop review workflow (PENDING → APPROVED → SENT) | SQLite dataclass-backed queue; audit trail required |
| `database_manager.py` | Multi-tenant invoice tracking (status: MISSING/RECEIVED/EMAILED/ESCALATED) | Every query must filter by `tenant_id`; no cross-tenant data leaks |
| `nav_secret_manager.py` | GCP Secret Manager integration for NAV credentials | TTL caching; never cache to disk |
| `auth.py` | JWT tokens + RBAC (ADMIN/ACCOUNTANT/SITE_MANAGER) | Enforce tenant context on all requests |
| `pdf_scanner.py` | PDF extraction + OCR (pytesseract for scanned invoices) | Extract: invoice #, amount, date, vendor contact |

### Deployment Topology

**Baseline (Current)**: Python scripts/CLI + SQLite + local PDF storage  
**Target**: Containerized services (Cloud Run) + PostgreSQL + GCS + Pub/Sub message bus

---

## 🔐 Multi-Tenant Isolation (CRITICAL)

**Rule**: Every piece of data and every operation must be scoped to `tenant_id`.

### Pattern (Database)
```python
# ✅ CORRECT: Tenant scoped
invoices = db.get_invoices(tenant_id, invoice_id)

# ❌ WRONG: Missing tenant filter
invoices = db.query("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
```

### Pattern (Auth)
```python
# Extract from JWT token; propagate to all functions
current_user = verify_jwt(token)
tenant_id = current_user.tenant_id  # Enforce in authZ layer

# Pass tenant_id through stack
db.get_invoices(tenant_id)
email_queue.get_pending(tenant_id)
cache_credentials(tenant_id, nav_creds)
```

### Files Enforcing This
- `database_manager.py`: Invoice & audit queries require `tenant_id`
- `approval_queue.py`: Queue items must include `tenant_id`
- `nav_secret_manager.py`: Secrets scoped per `{prefix}-{tenant_id}`
- `auth.py`: `verify_jwt()` extracts tenant from token

---

## 🛡️ Security Patterns

### 1. Credential Protection (NAV Secrets)
- **Never hardcode or log credentials**
- Store only in GCP Secret Manager (or env vars for dev)
- In-memory TTL cache in `NavSecretManager` (5 min default)
- NAV password must be hashed before API submission

### 2. Prompt Injection Prevention (AI Safety)
**Files**: `invoice_agent.py` (InputSanitizer, OutputValidator)

```python
# Pattern: Sanitize → Invoke → Validate
sanitized_vendor = InputSanitizer.sanitize_text(vendor_name, max_len=100)
draft_email = invoke_gemini(template, sanitized_vendor, invoice_data)
if not OutputValidator.is_safe(draft_email):
    raise ValueError("LLM output failed safety check")
```

### 3. Data Classification
- **CRITICAL** (secrets vault): NAV credentials, signing keys
- **HIGH** (encryption at rest): Invoice PDFs, metadata, vendor contacts
- **MEDIUM** (sanitized logs): Operation logs (no PII/secrets)

---

## 🧪 Testing Conventions

### ✅ Production Testing Gap
**Critical blocker**: System has **70 passing unit tests but ZERO live API tests**.
- All current tests mock NAV responses
- Framework requires live API validation before production
- See `CRITICAL_FINDINGS.md` for details

### Testing Patterns
```python
# ✅ Unit tests: Mock external calls
@patch('requests.post')
def test_nav_query(mock_post):
    mock_post.return_value.content = b"<result><funcCode>OK</funcCode></result>"
    result = nav_client.query_invoices(creds)
    assert result.is_success

# ❌ Not in current codebase (needs implementation):
# - Live NAV API tests (see test_nav_live_api.py setup docs)
# - Integration tests with actual approval workflow
# - End-to-end PDF → AI → Email tests
```

### Test Files by Coverage Area
| File | Focus |
|------|-------|
| `test_nav_client.py` | NavClient XML/crypto logic |
| `test_invoice_agent.py` | Gemini API + safety guards |
| `test_manage_invoice.py` | Database ops (mocked DB) |
| `test_auth.py` | JWT + RBAC validation |
| `test_nav_live_api.py` | **LIVE API TEST** (requires NAV credentials) |

---

## 🛠️ Developer Workflows

### Local Development Setup
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment (dev secrets)
export GOOGLE_CLOUD_PROJECT=your-project
export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
export JWT_SECRET_KEY=dev-secret-key

# 3. Run unit tests
python -m pytest tests/ -v

# 4. Live API test (requires NAV credentials)
python -m pytest test_nav_live_api.py -v
```

### Database Migrations
- Database schema lives in `database_manager.py` (create_schema() method)
- Always add migration docstring with version + date
- Test against both SQLite (dev) and PostgreSQL (target)

### Adding New Features
1. **Identify tenant boundary**: Does this cross tenants? If yes, add `tenant_id` parameter
2. **Update auth.py if new role needed**: Add to `UserRole` enum + RBAC check
3. **Add tests**: Unit tests with mocks; optional: live test if external API involved
4. **Audit logging**: Every state change → audit log with `tenant_id`, `user_id`, `timestamp`

---

## 📋 Key Files & Patterns

| File | Key Pattern |
|------|-------------|
| `nav_client.py` | **NavErrorCode enum** distinguishes retryable (OPERATION_FAILED) vs permanent (INVALID_CREDENTIALS) errors; retry logic must respect this |
| `invoice_agent.py` | **Triple validation**: InputSanitizer → Gemini → OutputValidator; LLM output MUST pass hallucination checks before queuing |
| `approval_queue.py` | **Status flow**: PENDING → (Approve/Reject/Edit) → APPROVED → SENT; all transitions logged to audit trail with `reviewed_by` + `reviewed_at` |
| `database_manager.py` | **Schema**: `invoices` (core) + `audit_log` (compliance); every write triggers audit record with old/new status |
| `auth.py` | **RBAC check decorator** (`@require_role('ADMIN')`) must extract tenant from JWT + validate user↔tenant matrix |

---

## 🚨 Production Readiness Checklist

- [ ] **Live NAV API tests passing** (test_nav_live_api.py)
- [ ] **All tenant_id filters verified** in database queries
- [ ] **Secrets NOT in code, logs, or git**
- [ ] **AI output validation** blocking hallucinated emails (esp. phantom URLs)
- [ ] **Audit trail** complete (every state change logged)
- [ ] **RBAC + tenant matrix** enforced (no users outside assigned tenants)
- [ ] **Error enum** updated for Sept 2025 VAT validation changes (VAT_RATE_MISMATCH, VAT_SUMMARY_MISMATCH)

---

## 🗺️ Roadmap (Baseline → Target)

**T1** (Current): Stabilize tenant boundaries + live API tests  
**T2**: Introduce FastAPI façade + containerization  
**T3**: Migrate SQLite → PostgreSQL + row-level security  
**T4**: Add Pub/Sub message bus for async workers  

See `ARCHITECTURE_TOGAF.md` for full TOGAF-aligned roadmap.
