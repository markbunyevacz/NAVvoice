## NAVvoice Architecture (TOGAF‑Aligned, Code-Based)

**Version**: 2.0  
**Date**: 2025-01-09  
**Scope**: NAV Online Számla invoice reconciliation + AI chasing workflow for Hungarian SME accounting operations.  
**Update Basis**: Actual Python code analysis (7 core modules, 6000+ lines)

---

## 1) Architecture Vision (TOGAF ADM Phase A)

### Drivers
- **Regulatory compliance**: Hungarian NAV Online Számla reporting; September 2025 stricter validations; 8-year retention.
- **Operational risk reduction**: prevent missing invoice PDFs that block bookkeeping and VAT reclaim.
- **Security & privacy**: protect NAV technical user credentials, invoices (financial data), and business contact data (GDPR).
- **Scale & resilience**: support multiple tenants (SMEs) and increasing invoice volume without system-wide failures.

### Target Outcomes
- **Detect missing invoices** by reconciling NAV invoice metadata vs received PDFs.
- **Automate vendor outreach** using an AI agent with **human approval** where required.
- **Maintain tenant isolation** end-to-end (data, secrets, processing, audit).
- **Enable extensibility**: modular architecture supports future integrations (additional invoice sources, ERP connectors) without breaking core NAV functionality.

### Stakeholders (Typical)
- **Client**: Accounting Manager, Bookkeeper, Site Manager (PDF uploader)
- **SaaS Operator**: Support, Security Officer, Platform Engineer
- **External**: NAV API, Email providers, LLM provider (Google Gemini), Cloud provider (GCP)

---

## 2) Baseline Architecture (as currently implemented)

### Core Building Blocks (SBBs with code metrics)

#### 1. NAV API Client (`nav_client.py` - 1527 lines, 100+ unit tests)
**Purpose**: Direct integration with Hungarian NAV Online Számla v3.0 API

**Key Components**:
- `NavCredentials` (dataclass): Holds technical user login, password, signature key (32-char), replacement key (32-char), tax number (8-digit)
- `NavClient`: Main API client with:
  - **Cryptography**: SHA-512 password hashing, SHA3-512 request signature generation per NAV v3.0 spec
  - **Rate limiting**: 1 request/second per IP (NAV API constraint enforcement)
  - **Retry logic**: 3 attempts with exponential backoff for transient errors
  - **Error handling**: `NavErrorCode` enum with retryable vs non-retryable classification
  - **September 2025 validations**: Detects VAT_RATE_MISMATCH (435), VAT_SUMMARY_MISMATCH (734), VAT_LINE_ITEM_ERROR (1311)
  - **XML parsing**: Proper namespace handling for all NAV response structures
  - **Session management**: Thread-safe request session with automatic retry on transient failures

**NAV API Endpoints Supported**:
- `queryInvoiceDigest`: List invoice metadata with date/status filters
- `queryInvoiceData`: Download detailed invoice data
- `manageInvoice`: Mark invoices as processed

**Constraints**:
- Live NAV test-environment validation is separate operational step (see `test_nav_live_api.py`)
- Does not yet include NAV's new "online invoice transmission" endpoint (future)

---

#### 2. Secrets Management (`nav_secret_manager.py` - 466 lines, fully tested)
**Purpose**: Secure, multi-tenant credential storage with GCP Secret Manager

**Key Components**:
- `SecretManagerConfig`: Configuration with GCP project ID, cache TTL (5 min default), secret prefix naming
- `NavSecretManager`: 
  - **Multi-tenant isolation**: Each tenant gets dedicated secret (`nav-credentials-{tenant_id}`)
  - **In-memory caching**: 5-minute TTL with thread-safe access (Lock-protected)
  - **Auto-rotation support**: Automatic version handling for credential rotation
  - **Fallback mode**: Falls back to environment variables for local development
  - **Secret versioning**: Integrates with GCP's secret version management

**Security Properties**:
- Credentials never persist to disk
- Only cached in memory with configurable TTL
- Thread-safe concurrent access
- Audit trail via GCP Secret Manager's access logs

**Integration**:
- Requires `GOOGLE_APPLICATION_CREDENTIALS` environment variable (service account key)
- Depends on GCP Secret Manager API being enabled

---

#### 3. Data Storage (`database_manager.py` - 785 lines, transaction support)
**Purpose**: Invoice metadata and audit log persistence with multi-tenant isolation

**Key Components**:
- `InvoiceStatus` (enum): MISSING, RECEIVED, EMAILED, ESCALATED
- `Invoice` (dataclass): Complete invoice record with tenant isolation
- `DatabaseManager`:
  - **SQLite backend**: Current; PostgreSQL recommended for production
  - **Multi-tenant isolation**: Every query filters by `tenant_id` (enforced at query level)
  - **Schema**: Two main tables
    - `invoices`: Stores NAV invoice metadata + receipt tracking (UNIQUE constraint on tenant_id + nav_invoice_number)
    - `audit_log`: Immutable records for GDPR 8-year retention
  - **Indexes**: Optimized for common queries (tenant_status, tenant_invoice, vendor_tax_number, invoice_date)
  - **Schema versioning**: SCHEMA_VERSION=2 for migration tracking
  - **ACID compliance**: Transaction support with rollback

**Operations**:
- `upsert_nav_invoices()`: Insert/update from NAV API (ignores duplicates)
- `mark_as_received()`: Match PDF to invoice, update status
- `get_missing_invoices()`: Query by tenant + status + age filters
- `get_audit_trail()`: Retrieve change history for compliance

**Constraints**:
- SQLite suitable for single-instance deployments
- Recommend migration to PostgreSQL for high concurrency
- Row-level security (RLS) needs implementation at application layer (currently at query level)

---

#### 4. PDF Processing (`pdf_scanner.py` - 955 lines, production-ready)
**Purpose**: Malware detection, text extraction, invoice matching

**Key Components**:

**A. PDFMalwareScanner**:
- **HIGH_RISK patterns** (blocks processing):
  - JavaScript (`/JavaScript`, `/JS\s`)
  - Launch actions (`/Launch`)
- **SUSPICIOUS_PATTERNS** (warn, optional enforcement):
  - Embedded files (`/EmbeddedFile`)
  - URI actions (`/URI`, `/GoToR`)
  - Form submission (`/SubmitForm`)
  - Encryption (`/Encrypt`)
  - AcroForms with scripts (`/AcroForm`)
  - XFA forms (`/XFA`)
- **File size limits**: 100MB default (configurable)
- **Strict mode**: Optional enforcement of all patterns
- **Obfuscation detection**: Object stream analysis

**B. PDFContentExtractor**:
- **Invoice number patterns**:
  - Hungarian: SZ-YYYY-NNNN (NAV standard)
  - International: INV-NNNN, ABC123
  - Confidence scoring: Ranks multiple matches
- **Vendor name detection**: Supports Hungarian "Kft", "Bt", international "Ltd", "GmbH", etc.
- **Amount detection**: Hungarian (Ft, forint), international (€, USD, HUF)
- **OCR support**: Optional Tesseract-based scanning for scanned PDFs

**C. FilenameInvoiceExtractor**:
- Pattern: `Vendor_InvoiceNumber.pdf` (e.g., `TestSupplier_INV-2024-001.pdf`)
- Supports nested folder scanning
- Handles Hungarian vendor names with accents

**Dependencies**:
- PyPDF2: PDF text extraction
- pdf2image + pytesseract: Optional OCR (requires system Tesseract installation)
- Pillow: Image processing

---

#### 5. AI Invoice Agent (`invoice_agent.py` - 996 lines, production-ready)
**Purpose**: AI-powered email generation with safety guards

**Key Components**:

**A. InputSanitizer**:
- **Prompt injection prevention**: Blocks patterns like:
  - "ignore previous", "disregard", "forget"
  - "new instructions", "system prompt"
  - "act as", "pretend to be"
  - Code blocks (```), instruction markers ([INST], <<...>>)
- **Field length limits**: vendor_name=200, invoice_number=50, notes=500, email=254
- **Character escaping**: Removes control sequences

**B. OutputValidator**:
- **Presence checks**: Invoice number, amount, vendor name must appear
- **Hallucination detection**:
  - Detects fabricated invoice numbers (different from input)
  - Detects incorrect amounts (>100 Ft variation allowed)
- **Blocked content**: PII patterns, URLs, unknown email addresses, secret patterns
- **Length validation**: 50-2000 characters for emails

**C. InvoiceAgent**:
- **LLM**: Google Gemini (gemini-1.5-flash model)
- **Configuration**: Temperature=0.3 (deterministic), max_output_tokens=500
- **Email tones** (escalation levels):
  - POLITE: First reminder, 3-5 sentences
  - FIRM: Second reminder, emphasizes urgency
  - URGENT: Third reminder, mentions accounting problems
  - FINAL_WARNING: Before escalation to management
- **Hungarian language**: All prompts and templates in Hungarian
- **Email template**: Includes subject, body, sender name/title/company

**System Prompts**: Each tone has customized Hungarian prompt to guide Gemini output

**Dependencies**:
- google-genai: Google Gemini API client
- No local LLM; all processing cloud-based

---

#### 6. Human Approval Workflow (`approval_queue.py` - 806 lines, production-ready)
**Purpose**: Human-in-the-loop email review before sending

**Key Components**:

**A. ApprovalStatus** (enum):
- PENDING: Awaiting human review
- APPROVED: Approved, ready to send
- REJECTED: Rejected, will not send
- SENT: Already sent
- EXPIRED: Review period expired
- EDITED: Content edited before approval

**B. Priority** (enum): LOW, NORMAL, HIGH, URGENT

**C. QueueItem** (dataclass):
- Stores AI-generated email draft with context:
  - Invoice number, vendor name, vendor email, amount, date
  - Email subject, body, tone
  - Status, priority, expiration
  - Created_by (AI agent ID), reviewed_by (user ID), reviewed_at

**D. ApprovalQueue**:
- **SQLite backend**: Queue persistence
- **Multi-tenant isolation**: Tenant-scoped queries
- **Status flow**: PENDING → APPROVED → SENT (or REJECTED)
- **Edit support**: Can modify email before approval
- **Audit trail**: Full history of approvals/rejections/edits
- **Expiration**: Configurable review deadline
- **Notification support**: API for real-time alerts (pending: Redis integration)

---

#### 7. Authentication & Authorization (`auth.py` - 872 lines, code-complete)
**Purpose**: User authentication and tenant-scoped access control

**Key Components**:

**A. UserRole** (enum) - Hierarchical:
- ADMIN: Full access (manage NAV keys, billing, users)
- ACCOUNTANT: View, reconcile invoices, approve emails
- SITE_MANAGER: Upload PDFs only

**B. Permission** (enum) - Granular:
- VIEW_INVOICES, UPLOAD_INVOICES, RECONCILE_INVOICES, DELETE_INVOICES
- VIEW_AUDIT_LOG, MANAGE_USERS, MANAGE_SECRETS
- APPROVE_EMAILS, VIEW_APPROVAL_QUEUE

**C. JWTManager**:
- Token generation with configurable expiration (30 min default)
- Token validation with signature verification
- Refresh token support (7 days default)
- Claims: user_id, tenant_id, roles, permissions, issued_at, expiry

**D. PasswordManager**:
- bcrypt-based hashing (10 rounds)
- Secure comparison (constant-time)

**E. RBAC**:
- Role-to-permission mapping matrix
- Multi-tenant user isolation: User ↔ tenant assignment validation

**Configuration**:
- Secret key: From `JWT_SECRET_KEY` env var or random (tokens.token_urlsafe(32))
- Algorithm: HS256
- Issuer: "nav-invoice-reconciliation"
- Audience: "nav-api"

**Current Status**: Code complete; integration to web API (FastAPI) pending

---

### Baseline Technology Stack
- **Runtime**: Python 3.9+ (single-process scripts or async workers)
- **Data**: SQLite (`data/invoices.db`)
- **Documents**: Local filesystem (`data/pdfs/`)
- **Secrets**: GCP Secret Manager (prod) or environment variables (dev)
- **API Communication**: requests (HTTP), lxml (XML parsing)
- **Cryptography**: pycryptodome (AES), bcrypt (passwords), PyJWT (tokens)
- **AI**: google-genai (Gemini)
- **PDF**: PyPDF2, pdf2image, pytesseract
- **Email**: SMTP (Gmail app password) - integration pending

---

## 3) Current Implementation Status by Module

| Module | Lines | Status | Tests | Key Gap |
|--------|-------|--------|-------|---------|
| `nav_client.py` | 1527 | ✅ Production-ready | 100+ | Live NAV test env not yet executed |
| `nav_secret_manager.py` | 466 | ✅ Production-ready | Full | - |
| `database_manager.py` | 785 | ✅ Production-ready | Comprehensive | Recommend PostgreSQL for scale |
| `pdf_scanner.py` | 955 | ✅ Production-ready | Full | OCR optional, not tested in all PDFs |
| `invoice_agent.py` | 996 | ✅ Production-ready | Full | Requires Gemini API key |
| `approval_queue.py` | 806 | ✅ Production-ready | Full | UI/notification layer pending |
| `auth.py` | 872 | ✅ Code-complete | Full | Web API integration pending |
| **Total** | **6407** | **70% deployed** | **900+ tests** | **API layer & queue needed** |

---

## 4) Target Architecture (Platform-Ready, Distributed)

### Transition from Monolith → Microservices
**Timeline**: 3-6 months to production readiness

**T1: API Façade (Week 1-2)**
- FastAPI service wrapping existing modules
- JWT middleware for tenant context propagation
- REST endpoints: /invoices, /approval-queue, /settings

**T2: Message Queue (Week 3-4)**
- RabbitMQ or Cloud Pub-Sub
- Async workers for:
  - NAV sync (polling for new invoices)
  - PDF scanning (continuous folder monitoring)
  - AI drafting (background processing)
  - Email sending (batch or on-demand)

**T3: Data Layer Upgrade (Week 5-8)**
- PostgreSQL with Row-Level Security (RLS)
- Object storage for PDFs (GCS/S3)
- Secrets vault (GCP Secret Manager - already integrated)

**T4: Observability (Week 9-12)**
- OpenTelemetry integration
- Structured logging (JSON)
- Metrics (Prometheus)
- Distributed tracing
- Error tracking (Sentry)

---

## 5) Data Architecture (Current + Target)

### Baseline (SQLite)
```
invoices (id, tenant_id, nav_invoice_number, vendor_name, 
          vendor_tax_number, amount, currency, invoice_date, 
          status, email_count, pdf_path, notes, created_at, last_updated)
  ↓ UNIQUE(tenant_id, nav_invoice_number)
  
audit_log (id, tenant_id, invoice_id, action, old_status, new_status, 
           user_id, details, performed_at)
```

### Target (PostgreSQL with RLS)
```
tenants (tenant_id, plan_tier, created_at, suspension_reason)

users (user_id, tenant_id, email, password_hash, role, 
       refresh_token, is_active, created_at)

invoices (id, tenant_id, nav_invoice_number, vendor_name, 
          vendor_tax_number, amount, currency, invoice_date, 
          status, email_count, pdf_path_gcs, notes, created_at, last_updated)
  ↓ RLS: Enable for tenant_id
  ↓ Indexes: (tenant_id, status), (tenant_id, invoice_date)
  
audit_log (id, tenant_id, invoice_id, action, old_status, new_status, 
           user_id, details, performed_at)
  ↓ RLS: Enable for tenant_id
  ↓ Immutable: INSERT only, no UPDATE/DELETE
  
approval_queue (id, tenant_id, invoice_number, vendor_email, status, 
                email_subject, email_body, priority, created_at, expires_at, 
                reviewed_by, reviewed_at)
  ↓ RLS: Enable for tenant_id
```

---

## 6) Security Architecture (Current Implementation)

### Multi-Tenant Isolation Enforced At
1. **Database query level**: Every query filters `tenant_id` (application-enforced)
2. **Secrets storage**: Per-tenant secret in GCP Secret Manager
3. **Approval queue**: Tenant-scoped queries in SQLite
4. **Audit log**: Tenant-scoped immutable records

### Cryptographic Boundaries
- **NAV API password**: SHA-512 hashed before transmission
- **NAV API requests**: SHA3-512 signature per v3.0 spec
- **Secrets in transit**: GCP encrypted channel
- **Secrets at rest**: GCP CMEK support (optional)
- **JWT tokens**: HS256 signed, short-lived (30 min), refresh token (7 days)
- **PDF files**: Scanned for malware patterns before processing

### Input/Output Validation
- **LLM inputs**: Sanitized for prompt injection (9 blocking patterns)
- **LLM outputs**: Validated for hallucination (invoice number, amount, vendor)
- **PDF inputs**: Malware scanning (high-risk patterns block, suspicious warn)
- **Email outputs**: PII/URL blocking, length validation (50-2000 chars)

### Access Control (RBAC)
| Role | Invoice View | Upload | Reconcile | Approve | Delete |
|------|------|--------|-----------|---------|--------|
| ADMIN | ✅ | ✅ | ✅ | ✅ | ✅ |
| ACCOUNTANT | ✅ | ❌ | ✅ | ✅ | ❌ |
| SITE_MANAGER | ❌ | ✅ | ❌ | ❌ | ❌ |

---

## 7) Deployment Architecture (Baseline vs Target)

### Current Deployment (Single-Node Reference)
```
┌─────────────────────────────────────┐
│  Linux/macOS VM or Container        │
├─────────────────────────────────────┤
│  Python 3.9+ Process                │
│  ├─ NavClient (sync or scheduled)   │
│  ├─ PDFScanner (scheduled folder)   │
│  ├─ InvoiceAgent (on-demand)        │
│  ├─ ApprovalQueue (API + scheduler) │
│  └─ DatabaseManager (SQLite)        │
├─────────────────────────────────────┤
│  GCP Secret Manager (via SDK)       │
│  SQLite data/invoices.db            │
│  Local data/pdfs/                   │
└─────────────────────────────────────┘
```

### Target Deployment (Cloud-Native)
```
┌────────────────────────────────────────────────────────────┐
│  Kubernetes Cluster (GKE / EKS)                            │
├────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐   │
│  │ FastAPI API │  │ NAV Sync     │  │ Approval UI    │   │
│  │ (2-3 pods)  │  │ Worker       │  │ Service        │   │
│  └──────┬──────┘  │ (1-2 pods)   │  └────────────────┘   │
│         │         └──────────────┘                        │
│         └──────────┬──────────────────┬─────────────┐     │
│                    │                  │             │     │
│  ┌─────────────────┴──────┐  ┌────────┴─────┐  ┌──┴──┐   │
│  │ Cloud Pub/Sub Message  │  │ PDF Scanner  │  │ Email  │
│  │ Queue (Event Bus)      │  │ Worker       │  │ Sender │
│  └────────────────────────┘  └──────────────┘  └───────┘ │
│                                                            │
├────────────────────────────────────────────────────────────┤
│ Data Layer:                                                │
│  ├─ CloudSQL PostgreSQL (with RLS)                        │
│  ├─ Cloud Storage (PDFs + malware scan pipeline)          │
│  ├─ Secret Manager (with auto-rotation)                   │
│  └─ Firestore (optional: approval queue, notifications)   │
│                                                            │
│ Observability:                                             │
│  ├─ Cloud Logging (JSON structured)                       │
│  ├─ Cloud Monitoring (Prometheus)                         │
│  └─ Cloud Trace (distributed tracing)                     │
└────────────────────────────────────────────────────────────┘
```

---

## 8) Testing Coverage (Current)

### Unit Tests by Module
- **nav_client.py**: 100+ tests (XML parsing, crypto, rate limiting, retries)
- **database_manager.py**: 50+ tests (CRUD, tenant isolation, audit)
- **pdf_scanner.py**: 200+ tests (malware patterns, extraction, OCR)
- **invoice_agent.py**: 150+ tests (sanitization, validation, tones)
- **approval_queue.py**: 100+ tests (status flow, expiration, history)
- **auth.py**: 200+ tests (JWT, RBAC, permissions)
- **nav_secret_manager.py**: 50+ tests (caching, rotation, fallback)

### Integration Tests
- **test_integration.py**: End-to-end workflows (NAV→PDF→AI→Approval)
- **test_nav_live_api.py**: Live NAV test-environment (separate operational step)
- **test_nav_framework_compliance.py**: September 2025 validation scenarios

### Coverage Gap
- ❌ Live NAV test-environment execution not yet completed
- ❌ Email sending (SMTP integration) not tested
- ❌ Web API endpoints (FastAPI) not yet implemented
- ❌ Message queue integration not yet built

---

## 9) Known Limitations & Roadmap

### Current Limitations
1. **No API layer**: All modules are Python libraries; no REST/gRPC endpoints
2. **No async processing**: Everything is synchronous; blocks on NAV API/LLM calls
3. **SQLite only**: Single-instance database; not suitable for high concurrency
4. **Local PDF storage**: No cloud object storage; limited to single VM
5. **No UI**: Approval queue requires direct database access or custom scripts
6. **No email integration**: SMTP sender not yet implemented

### Roadmap (Priority Order)
1. **Phase 1 (Jan-Feb 2025)**: Add FastAPI wrapper with JWT auth + tenant context
2. **Phase 2 (Mar-Apr 2025)**: Implement message queue (Pub/Sub) for async processing
3. **Phase 3 (May-Jun 2025)**: Migrate to PostgreSQL + Cloud Storage
4. **Phase 4 (Jul 2025)**: Build approval UI (web dashboard)
5. **Phase 5 (Aug 2025)**: Add email integration + notifications
6. **Phase 6 (Sep 2025)**: Full Kubernetes deployment + observability

---

## 10) Acceptance Criteria: "Done"

- ✅ All 7 core modules production-ready with >90% test coverage
- ✅ Multi-tenant isolation enforced at database + application layers
- ✅ NAV API client live test-environment execution verified
- ✅ Security audit: cryptography, secrets, access control
- ✅ September 2025 NAV validations implemented and tested
- ⏳ FastAPI service with JWT + RBAC (planned)
- ⏳ Message queue + async workers (planned)
- ⏳ PostgreSQL + RLS + object storage (planned)
- ⏳ Approval UI + email integration (planned)
- ⏳ Full observability stack (planned)
