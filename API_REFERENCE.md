# API Reference (Public APIs, Functions, and Components)

This repository is a **NAV Online Számla invoice reconciliation toolkit**. The “public surface area” is primarily a set of Python modules (components) you can import and compose:

- `auth.py`: JWT auth + RBAC + in-memory user store + middleware helper
- `nav_client.py`: NAV Online Számla v3.0 XML client (queries + manageInvoice writes)
- `nav_secret_manager.py`: Google Cloud Secret Manager wrapper for multi-tenant NAV credentials
- `database_manager.py`: SQLite persistence for invoices + audit log (multi-tenant)
- `pdf_scanner.py`: PDF malware scanning + invoice number extraction + folder scan CLI
- `invoice_agent.py`: Gemini-powered Hungarian email generation + SMTP mailer + workflow orchestrator
- `approval_queue.py`: human-in-the-loop approval queue (SQLite)

It also contains a **planned** REST API surface (not implemented in code here) in `navvoice_api_endpoints.csv`.

---

## Quickstart

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### System dependencies (optional OCR)

If you want OCR fallback for scanned PDFs:

```bash
sudo apt-get update
sudo apt-get install -y tesseract-ocr poppler-utils
```

### Environment variables (common)

- **NAV API (example variables used by `nav_client.py` demo / live tests)**
  - `NAV_TECHNICAL_USER`, `NAV_PASSWORD`, `NAV_SIGNATURE_KEY`, `NAV_REPLACEMENT_KEY`, `NAV_TAX_NUMBER`
  - (Live tests) `NAV_TEST_LOGIN`, `NAV_TEST_PASSWORD`, `NAV_TEST_SIGNATURE_KEY`, `NAV_TEST_REPLACEMENT_KEY`, `NAV_TEST_TAX_NUMBER`, `NAV_TEST_SOFTWARE_ID`
- **Google Cloud Secret Manager**
  - `GOOGLE_APPLICATION_CREDENTIALS` (service account JSON)
  - `GCP_PROJECT_ID`
- **Gemini**
  - `GEMINI_API_KEY`
- **SMTP (Gmail)**
  - You’ll typically pass these via `MailerConfig` rather than env vars.

---

## Module: `auth.py` (Authentication + Authorization)

### Components

#### `AuthConfig`
Configuration for JWT issuance and validation.

- **Fields**
  - `secret_key`: defaults from `JWT_SECRET_KEY` or a generated random secret
  - `algorithm`: default `HS256`
  - `access_token_expire_minutes`: default `30`
  - `refresh_token_expire_days`: default `7`
  - `issuer`: default `nav-invoice-reconciliation`
  - `audience`: default `nav-api`

#### `UserRole` (enum)
`ADMIN`, `ACCOUNTANT`, `SITE_MANAGER`

#### `Permission` (enum)
Fine-grained permissions like `VIEW_INVOICES`, `UPLOAD_INVOICES`, `MANAGE_USERS`, `QUERY_NAV`, etc.

#### `ROLE_PERMISSIONS` (mapping)
Role → list of permissions.

#### `User` (dataclass)
Represents a user account.

- **Important methods**
  - `has_permission(permission: Permission) -> bool`
  - `to_dict() -> dict` (excludes password hash)

#### `PasswordManager`
bcrypt-based password hashing + strength validation.

- `hash_password(password: str) -> str`
- `verify_password(password: str, password_hash: str) -> bool`
- `validate_password_strength(password: str) -> tuple[bool, list[str]]`

#### `JWTManager`
Generates, validates, refreshes, and revokes JWTs.

- `generate_tokens(user: User) -> tuple[str, str]` (access, refresh)
- `validate_token(token: str, token_type: str = "access") -> dict | None`
- `revoke_token(token: str) -> bool`
- `refresh_access_token(refresh_token: str, user: User) -> str | None`

#### `AuthMiddleware`
Framework-agnostic request authentication helper.

- `authenticate_request(authorization_header: str | None, required_permissions: list[Permission] | None = None) -> tuple[bool, User | None, str | None]`

#### `UserStore`
In-memory user store (replace with DB in production).

- `create_user(email, password, role, tenant_id, name="") -> User`
- `authenticate(email, password) -> User | None`
- `get_user_by_email(email) -> User | None`
- `get_user_by_id(user_id, tenant_id) -> User | None`
- `get_users_by_tenant(tenant_id) -> list[User]`
- `update_user_role(user_id, new_role) -> bool`
- `deactivate_user(user_id) -> bool`

#### `AuthService`
High-level wrapper combining `JWTManager`, `UserStore`, `AuthMiddleware`.

- `register(...) -> User`
- `login(email, password) -> dict | None` (tokens + user info)
- `logout(token) -> bool` (revocation)
- `refresh(refresh_token) -> dict | None`
- `validate_request(authorization_header, required_permissions=None) -> (bool, User | None, str | None)`

### Usage examples

#### 1) Register + login + permission check

```python
from auth import AuthConfig, AuthService, UserRole, Permission

auth = AuthService(AuthConfig(secret_key="dev-secret"))

auth.register(
    email="accountant@example.com",
    password="SecurePass123!",
    role=UserRole.ACCOUNTANT,
    tenant_id="tenant-001",
    name="Main Accountant",
)

tokens = auth.login("accountant@example.com", "SecurePass123!")
assert tokens is not None

ok, user, err = auth.validate_request(
    f"Bearer {tokens['access_token']}",
    required_permissions=[Permission.VIEW_INVOICES],
)
assert ok, err
```

#### 2) Token refresh

```python
new_tokens = auth.refresh(tokens["refresh_token"])
assert new_tokens is not None
```

### Notes / constraints

- `require_auth(...)` exists as a decorator stub and raises `NotImplementedError` (it’s a placeholder for a real web framework integration).
- Token revocation is in-memory (`JWTManager._revoked_tokens`), so it is **not durable** across process restarts.

---

## Module: `nav_client.py` (NAV Online Számla v3.0 Client)

### Public constants

- `NAV_API_BASE_URL`: production base URL
- `NAV_API_TEST_URL`: test base URL
- `NAMESPACES`: XML namespace map used throughout requests/responses

### Components

#### `NavErrorCode` (enum)
Includes retryable transient errors and Sept 2025 validation error codes (`"435"`, `"734"`, `"1311"`).

#### `NavCredentials` (dataclass)
Holds technical user credentials and validates basic constraints.

- **Fields**
  - `login`, `password`
  - `signature_key` (**exactly 32 chars**)
  - `replacement_key` (**exactly 32 chars**; often hex for AES-128 key material)
  - `tax_number` (**8 digits**)

#### `NavApiError` (exception)
Raised for NAV-level errors (or mapped transport issues).

- **Fields**
  - `code`, `message`, `technical_message`
- **Property**
  - `is_retryable: bool`

#### `NavClient`
Primary client. Supports rate limiting (1 req/sec) and retries for retryable errors.

##### Core “public” methods

- `test_connection() -> bool`
- `query_invoice_data(invoice_number: str, invoice_direction: str = "INBOUND") -> dict`
- `query_invoice_digest(invoice_direction: str, issue_date_from: str, issue_date_to: str, page: int = 1, fetch_all_pages: bool = True, supplier_tax_number: str | None = None, invoice_category: str | None = None, relational_params: dict | None = None) -> list[dict]`
- Convenience wrappers:
  - `query_incoming_invoices(...)`
  - `query_outgoing_invoices(...)`
  - `query_incoming_invoice_digest(...)`
  - `query_outgoing_invoice_digest(...)`
- Write operations:
  - `token_exchange() -> str`
  - `manage_invoice(invoice_operations: list[dict], validate_sept_2025: bool = True) -> str`
- Transaction endpoints:
  - `query_transaction_status(transaction_id: str, return_original_request: bool = False) -> dict`
  - `query_transaction_list(date_time_from: str, date_time_to: str, page: int = 1, fetch_all_pages: bool = True, invoice_direction: str | None = None, transaction_status: str | None = None, request_status: str | None = None) -> list[dict]`

### Usage examples

#### 1) Query inbound invoice digests

```python
from nav_client import NavClient, NavCredentials

creds = NavCredentials(
    login="technicalUser",
    password="password123",
    signature_key="12345678901234567890123456789012",
    replacement_key="0123456789abcdef0123456789abcdef",
    tax_number="12345678",
)

client = NavClient(creds, use_test_api=True, software_id="HU12345678-0001")

digests = client.query_incoming_invoices("2024-01-01", "2024-01-31")
print(len(digests))
```

#### 2) Fetch full invoice XML by invoice number

```python
full = client.query_invoice_data("INV-2024-001", invoice_direction="INBOUND")
decoded_xml_bytes = full.get("invoice_data_decoded", b"")
```

#### 3) Submit invoice(s) with Sept 2025 pre-validation

```python
import base64

invoice_xml = b"<Invoice>...</Invoice>"
ops = [{
    "index": 1,
    "operation": "CREATE",  # CREATE | MODIFY | STORNO
    "invoiceData": base64.b64encode(invoice_xml).decode("utf-8"),
}]

transaction_id = client.manage_invoice(ops, validate_sept_2025=True)
status = client.query_transaction_status(transaction_id)
```

### Notes / constraints

- **Rate limiting**: enforced client-side (~1 request/second).
- **Retry policy**: only for `NavApiError.is_retryable == True` (transient errors).
- **Sept 2025 validation**: `manage_invoice(..., validate_sept_2025=True)` performs local checks to catch errors that will become blocking.

---

## Module: `nav_secret_manager.py` (GCP Secret Manager for NAV credentials)

### Components

#### `SecretManagerConfig` (dataclass)

- `project_id: str`
- `cache_ttl_seconds: int = 300`
- `enable_caching: bool = True`
- `secret_prefix: str = "nav-credentials"`
- `get_secret_name(tenant_id) -> str` (resource name ending in `/versions/latest`)
- `get_secret_id(tenant_id) -> str` (secret ID without version)

#### `NavSecretManager`
Thread-safe wrapper around `google-cloud-secret-manager` with optional in-memory caching.

- `get_credentials(tenant_id: str, bypass_cache: bool = False) -> NavCredentials`
- `store_credentials(tenant_id: str, credentials: NavCredentials, labels: dict | None = None) -> str`
- `rotate_credentials(tenant_id: str, new_credentials: NavCredentials) -> str`
- `invalidate_cache(tenant_id: str | None = None) -> None`
- `create_nav_client(tenant_id: str, use_test_api: bool = False, software_id: str | None = None) -> NavClient`
- `list_tenants() -> list[str]`
- `delete_credentials(tenant_id: str) -> None` (**dangerous / permanent**)

#### Exceptions

- `SecretManagerError` (base)
  - `SecretNotFoundError`
  - `SecretAccessError`
  - `SecretParseError`

### Usage example

```python
from nav_secret_manager import SecretManagerConfig, NavSecretManager
from nav_client import NavCredentials

cfg = SecretManagerConfig(project_id="my-gcp-project")
sm = NavSecretManager(cfg)

sm.store_credentials(
    tenant_id="tenant-001",
    credentials=NavCredentials(
        login="tech",
        password="pass",
        signature_key="12345678901234567890123456789012",
        replacement_key="0123456789abcdef0123456789abcdef",
        tax_number="12345678",
    ),
)

client = sm.create_nav_client("tenant-001", use_test_api=True, software_id="HU12345678-0001")
```

---

## Module: `database_manager.py` (SQLite invoice tracking + audit log)

### Components

#### `InvoiceStatus` (enum)
`MISSING`, `RECEIVED`, `EMAILED`, `ESCALATED`

#### `Invoice` (dataclass)
Represents an invoice record. Includes `tenant_id` for isolation.

#### `DatabaseManager`
Creates and manages the SQLite schema; all “tenant-safe” operations require a `tenant_id`.

##### Lifecycle

- `__init__(db_path: str = "data/invoices.db")`
- `initialize() -> None`

##### Import / update

- `upsert_nav_invoices(tenant_id: str, invoices: list[dict], user_id: str = "system") -> tuple[int, int]`
  - Returns `(inserted_count, skipped_count)`

- `mark_as_received(tenant_id: str, invoice_number: str, pdf_path: str | None = None, notes: str | None = None, user_id: str = "system") -> bool`

- `mark_as_emailed(tenant_id: str, invoice_number: str, user_id: str = "system") -> bool`

##### Queries

- `get_missing_invoices(tenant_id: str, days_old: int = 5) -> list[dict]`
- `get_invoices_needing_followup(tenant_id: str) -> list[dict]`
- `get_invoice(invoice_number: str, tenant_id: str | None = None) -> dict | None`
  - If `tenant_id is None`, it performs a cross-tenant lookup (intended for admin use only).
- `get_invoices_by_status(tenant_id: str, status: InvoiceStatus) -> list[dict]`
- `get_invoices_by_vendor(tenant_id: str, vendor_tax_number: str) -> list[dict]`
- `get_statistics(tenant_id: str) -> dict`
- `search_invoices(tenant_id: str, query: str, limit: int = 50) -> list[dict]`

##### Audit

- `get_audit_log(tenant_id: str, invoice_number: str | None = None, limit: int = 100) -> list[dict]`

##### Bulk / admin

- `bulk_mark_received(tenant_id: str, invoice_numbers: list[str], pdf_folder: str, user_id: str = "system") -> int`
- `delete_invoice(tenant_id: str, invoice_number: str) -> bool`
- `get_all_tenants() -> list[str]` (admin)
- `get_tenant_summary() -> list[dict]` (admin)

### Usage example (multi-tenant safe)

```python
from database_manager import DatabaseManager

db = DatabaseManager("data/invoices.db")
db.initialize()

tenant_id = "tenant-001"
inserted, skipped = db.upsert_nav_invoices(
    tenant_id,
    invoices=[{
        "invoiceNumber": "INV-2024-001",
        "supplierName": "Supplier Kft.",
        "supplierTaxNumber": "12345678",
        "grossAmount": 125000,
        "invoiceDate": "2024-01-15",
    }],
    user_id="system",
)

missing = db.get_missing_invoices(tenant_id, days_old=5)
```

---

## Module: `pdf_scanner.py` (PDF scanning + extraction + CLI)

### Components

#### `PDFMalwareScanner`
Heuristic PDF pre-scan to detect risky content (JavaScript, Launch actions, embedded files).

- `scan_file(pdf_path: Path) -> tuple[bool, list[str]]`
- `scan_batch(pdf_paths: list[Path]) -> dict[str, tuple[bool, list[str]]]`

#### `PDFContentExtractor`
Extracts text (PyPDF2) and optionally OCR (tesseract), then detects:
- invoice numbers
- vendor name
- amounts

Key methods:

- `extract_text(pdf_path: Path) -> tuple[str, str]` (text, method: `pypdf2|ocr|none`)
- `find_invoice_numbers(text: str) -> list[tuple[str, float]]`
- `find_vendor_name(text: str) -> str | None`
- `find_amount(text: str) -> float | None`
- `extract_invoice_data(pdf_path: Path) -> dict`

#### `ScannedPDF` (dataclass)
Represents extracted metadata for a single PDF.

#### `ScanResult` (dataclass)
Aggregated scan results.

#### `PDFScanner`
Folder scanning component that:
1) parses invoice numbers from filenames, then
2) optionally falls back to content scanning / OCR.

Key methods:

- `scan_folder(folder_path: str, recursive: bool = True, dry_run: bool = False, content_fallback: bool = True) -> ScanResult`
- `scan_single_pdf(pdf_path: Path) -> ScannedPDF`
- `extract_invoice_number(filename: str) -> str | None`
- `suggest_matches(pdf_path: Path) -> list[dict]`

### CLI usage

`pdf_scanner.py` can be used as a script:

```bash
python pdf_scanner.py data/pdfs --database data/invoices.db --dry-run --verbose
```

### Notes / constraints

- OCR is optional and requires system packages (see Quickstart).
- The scanner expects a DB-like object with `get_invoice(...)`, `mark_as_received(...)`, and `search_invoices(...)`.
  - If you are enforcing strict multi-tenancy with `DatabaseManager`, consider wrapping it in a tenant-scoped adapter so folder scans cannot accidentally do cross-tenant lookups.

---

## Module: `approval_queue.py` (Human-in-the-loop approval queue)

### Components

#### `ApprovalStatus` (enum)
`pending`, `approved`, `rejected`, `sent`, `expired`, `edited`

#### `Priority` (enum)
`LOW=1`, `NORMAL=2`, `HIGH=3`, `URGENT=4`

#### `QueueItem` (dataclass)
Email item awaiting approval, includes `tenant_id`.

#### `ApprovalQueue`
SQLite-backed queue with an action history table.

Key methods:

- `initialize() -> None`
- `add_to_queue(...) -> str` (returns item id)
- `get_pending_emails(tenant_id: str | None = None, limit: int = 50) -> list[QueueItem]`
- `get_approved_emails(tenant_id: str | None = None, limit: int = 50) -> list[QueueItem]`
- `get_item(item_id: str) -> QueueItem | None`
- `approve(item_id: str, user_id: str, notes: str | None = None) -> bool`
- `reject(item_id: str, user_id: str, reason: str) -> bool`
- `edit_and_approve(item_id: str, user_id: str, new_subject: str | None = None, new_body: str | None = None, notes: str | None = None) -> bool`
- `mark_as_sent(item_id: str, user_id: str = "system") -> bool`
- `expire_old_items() -> int`
- `get_statistics(tenant_id: str | None = None) -> QueueStatistics`
- `get_action_history(item_id: str, limit: int = 50) -> list[ApprovalAction]`

### Usage example

```python
from approval_queue import ApprovalQueue, Priority

q = ApprovalQueue("data/approvals.db")
q.initialize()

item_id = q.add_to_queue(
    tenant_id="tenant-001",
    invoice_number="INV-2024-001",
    vendor_name="Supplier Kft.",
    vendor_email="vendor@example.com",
    email_subject="Hiányzó számla: INV-2024-001",
    email_body="Tisztelt Partnerünk, ...",
    email_tone="polite",
    amount=125000,
    invoice_date="2024-01-15",
    priority=Priority.HIGH,
    created_by="ai-agent",
)

q.approve(item_id, user_id="accountant@company.hu")
```

---

## Module: `invoice_agent.py` (AI email generation + SMTP + orchestration)

### Components

#### `AgentConfig` (dataclass)
Gemini model configuration and sender identity.

#### `EmailTone` (enum)
`POLITE`, `FIRM`, `URGENT`, `FINAL`

#### `InputSanitizer`
Blocks common prompt injection patterns; escapes HTML; enforces max lengths.

- `sanitize(value: str, field_name: str = "text") -> str`
- `sanitize_dict(data: dict) -> dict[str, str]`
- `sanitize_invoice_data(...) -> dict[str, str]`

#### `OutputValidator`
Validates generated email content (invoice number/amount present, blocks phishing-like content).

- `validate(generated_text, expected_invoice_number, expected_amount, expected_vendor) -> tuple[bool, list[str]]`
- `sanitize_output(text: str) -> str`

#### `InvoiceAgent`
Gemini-based generator.

- `generate_chasing_email(vendor: str, invoice_num: str, amount: float, date: str, tone: EmailTone = EmailTone.POLITE, additional_context: str | None = None) -> dict`
- `generate_batch_emails(invoices: list[dict], tone: EmailTone = EmailTone.POLITE) -> list[dict]`

#### `VendorDirectory`
Mock in-memory vendor contact lookup (tax number and fuzzy name matching).

#### `MailerConfig` (dataclass) and `Mailer`
SMTP sender with optional `dry_run`.

- `send_email(to_email, subject, body, cc=None, reply_to=None) -> dict`
- `send_invoice_reminder(invoice: dict, email_content: dict) -> dict`
- `stats -> dict[str, int]`

#### `InvoiceReminderOrchestrator`
Ties DB + agent + mailer together to send reminders for missing invoices.

- `process_missing_invoices(days_old: int = 5, max_emails: int = 10) -> dict`

### Usage examples

#### 1) Generate one email (mocked example structure)

```python
from invoice_agent import InvoiceAgent, AgentConfig, EmailTone

agent = InvoiceAgent(AgentConfig(api_key="YOUR_GEMINI_API_KEY"))
result = agent.generate_chasing_email(
    vendor="Supplier Kft.",
    invoice_num="INV-2024-001",
    amount=125000,
    date="2024-01-15",
    tone=EmailTone.POLITE,
)

if result["success"]:
    print(result["email_subject"])
    print(result["email_body"])
```

#### 2) Send an email (dry run)

```python
from invoice_agent import Mailer, MailerConfig

mailer = Mailer(MailerConfig(
    sender_email="you@gmail.com",
    sender_password="gmail_app_password",
    dry_run=True,
))

mailer.send_email("vendor@example.com", "Subject", "Body")
```

### Notes / constraints

- Gemini access requires `google-genai` and a valid API key.
- Output validator blocks URLs and other phishing-like content; if your use case requires safe links, you’ll need to adjust the validator policy.
- The orchestrator currently assumes a DB API that may differ from `DatabaseManager`’s tenant-required methods; treat it as a workflow scaffold unless you wire tenant context explicitly.

---

## Planned REST API: `navvoice_api_endpoints.csv` (design-time surface)

The file `navvoice_api_endpoints.csv` lists **planned** HTTP endpoints (paths, auth expectations, scopes, and rate limits). This repo snapshot does not include an implemented FastAPI/Flask server for these routes, but you can use this CSV as the canonical contract for API gateway + backend implementation planning.

Example rows include:
- `/api/v1/auth/token` (JWT token exchange)
- `/api/v1/invoice/query` (invoice status query)
- `/api/v1/audit/logs` (GDPR access)

---

## End-to-end “happy path” (recommended composition)

1) **Authenticate** a user for a tenant with `AuthService`
2) **Fetch invoices** from NAV with `NavClient`
3) **Persist** them for a tenant with `DatabaseManager.upsert_nav_invoices(tenant_id, ...)`
4) **Match PDFs** using `PDFScanner` (filename/content extraction) and mark invoices received
5) **Generate reminder emails** for remaining missing invoices with `InvoiceAgent`
6) **Queue for approval** with `ApprovalQueue`
7) **Send approved emails** via `Mailer`, then mark invoices emailed in DB

