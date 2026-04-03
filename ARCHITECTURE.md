# NAV Invoice Reconciliation System Architecture

This document describes the architecture of the NAV Invoice Reconciliation System, an automated solution for tracking, reconciling, and chasing missing invoices using the Hungarian Tax Authority (NAV) Online Számla API and AI-powered email generation.

## 1. System Overview

The system is designed to bridge the gap between invoices reported to NAV and the actual PDF receipts available to the accounting team. It automates the detection of missing invoices and facilitates professional communication with vendors to request them.

### Key Capabilities
- **Automated Sync**: Daily synchronization with NAV Online Számla v3.0 API.
- **Missing Invoice Detection**: Identifies invoices reported to NAV but missing from local records.
- **AI-Powered Chasing**: Generates professional, context-aware reminder emails using Google Gemini.
- **Human-in-the-loop**: Approval queue for reviewing AI-generated emails before sending.
- **Security**: Enterprise-grade security with RBAC, encrypted credential storage, and audit logging.

## 2. High-Level Architecture

The system follows a modular architecture with clear separation of concerns.

```mermaid
graph TD
    User((User))
    Admin((Admin))
    Vendor((Vendor))

    subgraph "NAV Invoice Reconciliation System"
        API[API Gateway]
        Auth[Auth Service]
        Orch[Orchestrator]
        
        subgraph "Core Services"
            NAVClient[NAV Client]
            Agent[Invoice Agent]
            Queue[Approval Queue]
            DB[Database Manager]
            Secret[Secret Manager]
        end
        
        subgraph "External Services"
            Gemini[Google Gemini AI]
            Gmail[Gmail SMTP]
            NAV[NAV Online Számla]
            SecretMgr[GCP Secret Manager]
        end
    end

    User -->|Login/Upload| API
    Admin -->|Manage Users/Keys| API
    
    API --> Auth
    API --> Orch
    
    Orch --> NAVClient
    Orch --> Agent
    Orch --> Queue
    Orch --> DB
    
    NAVClient -->|Fetch Invoices| NAV
    NAVClient -->|Get Creds| Secret
    Secret -->|Retrieve| SecretMgr
    
    Agent -->|Generate Email| Gemini
    Agent -->|Validate| DB
    
    Queue -->|Store| DB
    Queue -->|Send| Gmail
    
    Gmail -->|Email| Vendor
```

## 3. Core Components

### 3.1 NAV Client (`nav_client.py`)
Handles all communication with the NAV Online Számla v3.0 API.
- **Features**:
  - Implements complex XML signature generation (SHA3-512).
  - Handles token exchange and session management.
  - Validates invoices against September 2025 blocking rules.
  - Automatic retry with exponential backoff for transient errors.
  - Rate limiting compliance (1 request/second).

### 3.2 Invoice Agent (`invoice_agent.py`)
AI agent responsible for generating professional communication.
- **Features**:
  - **Input Sanitization**: Prevents prompt injection attacks.
  - **Context-Aware Generation**: Uses invoice metadata to craft specific messages.
  - **Tone Adjustment**: Supports multiple escalation levels (Polite → Firm → Urgent).
  - **Output Validation**: Detecting hallucinations (wrong amounts/numbers) before approval.

### 3.3 Database Manager (`database_manager.py`)
Manages persistence for invoices and audit logs.
- **Features**:
  - **Multi-Tenancy**: Strict data isolation using `tenant_id`.
  - **Audit Logging**: Tracks all status changes for compliance (GDPR).
  - **Schema**: SQLite based (extensible to PostgreSQL).
  - **Status Tracking**: Tracks lifecycle: `MISSING` → `RECEIVED` or `EMAILED` → `ESCALATED`.

### 3.4 Approval Queue (`approval_queue.py`)
Implements the human-in-the-loop workflow.
- **Features**:
  - Queues AI-generated emails for review.
  - Supports Approve, Reject, and Edit workflows.
  - Tracks reviewer actions and timestamps.
  - Handles expiration of stale queue items.

### 3.5 Auth Service (`auth.py`)
Manages authentication and authorization.
- **Features**:
  - **RBAC**: Role-Based Access Control (Admin, Accountant, Site Manager).
  - **JWT**: Stateless authentication with access/refresh tokens.
  - **Security**: Bcrypt password hashing and robust validation.

### 3.6 Secret Manager (`nav_secret_manager.py`)
Securely stores sensitive credentials.
- **Features**:
  - Integration with Google Cloud Secret Manager.
  - Encryption at rest.
  - In-memory caching with TTL to minimize API calls.
  - Multi-tenant isolation for credentials.

## 4. Key Workflows

### 4.1 Daily Synchronization Flow
This process runs daily to fetch new invoices and identify missing ones.

```mermaid
sequenceDiagram
    participant Scheduler
    participant Orch as Orchestrator
    participant NAV as NAV Client
    participant DB as Database
    participant Agent as AI Agent
    participant Queue as Approval Queue

    Scheduler->>Orch: Trigger Daily Sync
    Orch->>NAV: Query Incoming Invoices (Last 30 days)
    NAV->>NAV: Authenticate (Token Exchange)
    NAV-->>Orch: Return Invoice List
    
    Orch->>DB: Upsert Invoices
    DB-->>Orch: Result (Inserted/Skipped)
    
    Orch->>DB: Get Missing Invoices (>5 days old)
    DB-->>Orch: List of Missing Invoices
    
    loop For Each Missing Invoice
        Orch->>Agent: Generate Reminder Email
        Agent->>Agent: Sanitize Inputs
        Agent->>Agent: Generate Content (Gemini)
        Agent->>Agent: Validate Output
        Agent-->>Orch: Email Content
        
        Orch->>Queue: Add to Approval Queue
        Queue-->>Orch: Queue Item ID
    end
```

### 4.2 Approval & Sending Flow
This workflow involves human review of the generated emails.

```mermaid
sequenceDiagram
    participant User
    participant API
    participant Auth
    participant Queue
    participant Mailer
    participant Vendor

    User->>API: Login(email, password)
    API->>Auth: Authenticate
    Auth-->>API: JWT Token
    API-->>User: Return Token

    User->>API: Get Pending Emails
    API->>Queue: Query Pending Items
    Queue-->>API: List of Emails

    alt Approve Email
        User->>API: Approve(item_id)
        API->>Queue: Update Status -> APPROVED
        Queue->>Mailer: Send Email
        Mailer->>Vendor: Send SMTP Email
        Mailer-->>Queue: Sent Success
        Queue->>Queue: Update Status -> SENT
    else Reject Email
        User->>API: Reject(item_id, reason)
        API->>Queue: Update Status -> REJECTED
    else Edit Email
        User->>API: Edit(item_id, new_content)
        API->>Queue: Update Content & Status -> APPROVED
    end
```

## 5. Security Architecture

### 5.1 Credential Management
- NAV Technical User credentials are **never** stored in code or plain text configuration files.
- They are stored in **Google Cloud Secret Manager**.
- Access is restricted via IAM roles.
- The application retrieves them only when needed and caches them briefly in memory.

### 5.2 Input Validation
- The `InputSanitizer` class in `invoice_agent.py` strips potential prompt injection attacks before sending data to the AI model.
- All API inputs are validated against strict schemas.

### 5.3 Output Validation
- The `OutputValidator` ensures the AI hasn't hallucinated data.
- It verifies that the invoice number and amount in the generated email match the database record exactly.
- It blocks sensitive patterns (e.g., unexpected credit card numbers).

### 5.4 Access Control
- **Admin**: Full system access.
- **Accountant**: Operational access (view invoices, approve emails).
- **Site Manager**: Limited access (upload receipts only).

## 6. Technology Stack

- **Language**: Python 3.10+
- **Database**: SQLite (Development), PostgreSQL (Production)
- **AI Model**: Google Gemini 1.5 Flash (via `google-genai` SDK)
- **Cloud Provider**: Google Cloud Platform (Secret Manager)
- **Authentication**: JWT + Bcrypt
- **External API**: NAV Online Számla v3.0 (XML/Rest)

## 7. Deployment Considerations

- **Environment Variables**:
  - `GOOGLE_APPLICATION_CREDENTIALS`: Path to GCP service account key.
  - `JWT_SECRET_KEY`: High-entropy secret for token signing.
  - `GEMINI_API_KEY`: API key for Google Gemini.
  - `GCP_PROJECT_ID`: Google Cloud Project ID.
- **Dependencies**: Listed in `requirements.txt`.
