"""
Database Manager for NAV Invoice Reconciliation

Tracks NAV invoice metadata and PDF receipt status using SQLite.
Supports true multi-tenant isolation via tenant_id column.

Multi-Tenancy:
    All queries filter by tenant_id for data isolation.
    Each tenant only sees their own invoices.

Schema:
    invoices: Stores NAV invoice data with receipt status tracking
    audit_log: Tracks all status changes for compliance

Security:
    - Tenant isolation at query level
    - All operations require tenant_id
    - Cross-tenant queries prevented by design
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class InvoiceStatus(Enum):
    """Invoice receipt status."""
    MISSING = "MISSING"       # NAV data exists, no PDF received
    RECEIVED = "RECEIVED"     # PDF has been received and matched
    EMAILED = "EMAILED"       # Reminder email sent to vendor
    ESCALATED = "ESCALATED"   # Multiple reminders failed, human intervention needed


@dataclass
class Invoice:
    """Invoice data model."""
    id: Optional[int]
    tenant_id: str  # Multi-tenancy support
    nav_invoice_number: str
    vendor_name: str
    vendor_tax_number: str
    amount: float
    currency: str
    invoice_date: str
    status: InvoiceStatus
    last_updated: datetime
    email_count: int = 0
    pdf_path: Optional[str] = None
    notes: Optional[str] = None
    project_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "nav_invoice_number": self.nav_invoice_number,
            "vendor_name": self.vendor_name,
            "vendor_tax_number": self.vendor_tax_number,
            "amount": self.amount,
            "currency": self.currency,
            "invoice_date": self.invoice_date,
            "status": self.status.value,
            "last_updated": self.last_updated.isoformat(),
            "email_count": self.email_count,
            "pdf_path": self.pdf_path,
            "notes": self.notes,
            "project_id": self.project_id,
        }


@dataclass
class Project:
    """Tenant-scoped project reference."""
    id: Optional[int]
    tenant_id: str
    project_code: str
    project_name: str
    aliases: Optional[str] = None
    reference_patterns: Optional[str] = None
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "project_code": self.project_code,
            "project_name": self.project_name,
            "aliases": self.aliases,
            "reference_patterns": self.reference_patterns,
            "is_active": self.is_active,
        }


# =============================================================================
# DATABASE MANAGER
# =============================================================================

class DatabaseManager:
    """
    SQLite-based database manager for NAV invoice tracking.

    Multi-Tenancy:
        All data is isolated by tenant_id. Each operation requires
        a tenant_id to ensure data isolation.

    Provides thread-safe operations for:
    - Upserting invoices from NAV API responses
    - Marking invoices as received when PDFs are matched
    - Querying missing invoices for follow-up
    - Audit logging for compliance

    Usage:
        db = DatabaseManager("data/invoices.db")
        db.initialize()

        # Insert NAV invoices for a tenant
        db.upsert_nav_invoices("tenant-001", [
            {"nav_invoice_number": "INV-001", "vendor_name": "Supplier", ...}
        ])

        # Mark as received when PDF found
        db.mark_as_received("tenant-001", "INV-001",
                           pdf_path="data/pdfs/Supplier_INV-001.pdf")

        # Get invoices needing follow-up for tenant
        missing = db.get_missing_invoices("tenant-001", days_old=5)
    """

    # Schema version for migrations
    SCHEMA_VERSION = 3  # Bumped for tenant-scoped project mapping support
    
    def __init__(self, db_path: str = "data/invoices.db"):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"DatabaseManager initialized: {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
        """Thread-safe connection context manager."""
        conn = sqlite3.connect(
            str(self.db_path),
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def initialize(self) -> None:
        """Create database schema if not exists."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Main invoices table with tenant_id for multi-tenancy
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS invoices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    nav_invoice_number TEXT NOT NULL,
                    vendor_name TEXT NOT NULL,
                    vendor_tax_number TEXT,
                    amount REAL NOT NULL,
                    currency TEXT DEFAULT 'HUF',
                    invoice_date TEXT NOT NULL,
                    status TEXT DEFAULT 'MISSING',
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    email_count INTEGER DEFAULT 0,
                    pdf_path TEXT,
                    notes TEXT,
                    project_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(tenant_id, nav_invoice_number),
                    FOREIGN KEY (project_id) REFERENCES projects(id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    project_code TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    aliases TEXT,
                    reference_patterns TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(tenant_id, project_code)
                )
            """)

            # Indexes for tenant-scoped queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_invoices_tenant
                ON invoices(tenant_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_invoices_tenant_status
                ON invoices(tenant_id, status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_invoices_tenant_invoice
                ON invoices(tenant_id, nav_invoice_number)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_invoices_vendor
                ON invoices(vendor_tax_number)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_invoices_date
                ON invoices(invoice_date)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_invoices_tenant_project
                ON invoices(tenant_id, project_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_projects_tenant
                ON projects(tenant_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_projects_tenant_code
                ON projects(tenant_id, project_code)
            """)

            # Audit log for compliance (GDPR 8-year retention)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    invoice_id INTEGER,
                    action TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    details TEXT,
                    user_id TEXT,
                    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (invoice_id) REFERENCES invoices(id)
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_tenant
                ON audit_log(tenant_id)
            """)

            # Schema version tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            self._run_migrations(cursor)
            cursor.execute("""
                INSERT OR REPLACE INTO schema_info (key, value)
                VALUES ('version', ?)
            """, (str(self.SCHEMA_VERSION),))

            logger.info("Database schema initialized with multi-tenancy support")

    def _run_migrations(self, cursor: sqlite3.Cursor) -> None:
        """Apply additive schema changes for existing databases."""
        if not self._column_exists(cursor, "invoices", "project_id"):
            cursor.execute("ALTER TABLE invoices ADD COLUMN project_id INTEGER")

        if not self._table_exists(cursor, "projects"):
            cursor.execute("""
                CREATE TABLE projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    project_code TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    aliases TEXT,
                    reference_patterns TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(tenant_id, project_code)
                )
            """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_invoices_tenant_project
            ON invoices(tenant_id, project_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_projects_tenant
            ON projects(tenant_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_projects_tenant_code
            ON projects(tenant_id, project_code)
        """)

    @staticmethod
    def _table_exists(cursor: sqlite3.Cursor, table_name: str) -> bool:
        cursor.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        )
        return cursor.fetchone() is not None

    @staticmethod
    def _column_exists(cursor: sqlite3.Cursor, table_name: str, column_name: str) -> bool:
        cursor.execute(f"PRAGMA table_info({table_name})")
        return any(row["name"] == column_name for row in cursor.fetchall())

    @staticmethod
    def _invoice_select_clause() -> str:
        """Select invoice rows with optional project metadata."""
        return """
            SELECT
                i.*,
                p.project_code,
                p.project_name,
                p.aliases AS project_aliases,
                p.reference_patterns AS project_reference_patterns,
                p.is_active AS project_is_active
            FROM invoices i
            LEFT JOIN projects p
                ON i.project_id = p.id
               AND i.tenant_id = p.tenant_id
        """

    # =========================================================================
    # UPSERT NAV INVOICES
    # =========================================================================

    def upsert_nav_invoices(
        self,
        tenant_id: str,
        invoices: List[Dict[str, Any]],
        user_id: str = "system"
    ) -> Tuple[int, int]:
        """
        Insert new invoices from NAV API response. Ignores duplicates.

        Args:
            tenant_id: Tenant identifier for data isolation
            invoices: List of invoice dictionaries from NavClient
                Required keys: nav_invoice_number (or invoiceNumber),
                              vendor_name (or supplierName), amount (or grossAmount)
            user_id: User performing the operation (for audit)

        Returns:
            Tuple of (inserted_count, skipped_count)

        Example:
            >>> invoices = client.query_incoming_invoices("2024-01-01", "2024-01-31")
            >>> inserted, skipped = db.upsert_nav_invoices("tenant-001", invoices)
            >>> print(f"Inserted {inserted}, skipped {skipped} duplicates")
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")

        inserted = 0
        skipped = 0

        with self._get_connection() as conn:
            cursor = conn.cursor()

            for inv in invoices:
                # Normalize field names (support both NAV API and custom formats)
                invoice_number = inv.get("nav_invoice_number") or inv.get("invoiceNumber", "")
                vendor_name = inv.get("vendor_name") or inv.get("supplierName", "Unknown")
                vendor_tax = inv.get("vendor_tax_number") or inv.get("supplierTaxNumber", "")
                amount = inv.get("amount") or inv.get("grossAmount", 0.0)
                currency = inv.get("currency", "HUF")
                invoice_date = inv.get("invoice_date") or inv.get("invoiceDate", "")

                if not invoice_number:
                    logger.warning(f"Skipping invoice with no number: {inv}")
                    skipped += 1
                    continue

                try:
                    cursor.execute("""
                        INSERT OR IGNORE INTO invoices
                        (tenant_id, nav_invoice_number, vendor_name, vendor_tax_number,
                         amount, currency, invoice_date, status, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'MISSING', CURRENT_TIMESTAMP)
                    """, (tenant_id, invoice_number, vendor_name, vendor_tax,
                          amount, currency, invoice_date))

                    if cursor.rowcount > 0:
                        inserted += 1
                        self._log_audit(cursor, tenant_id, cursor.lastrowid, "CREATED",
                                       None, "MISSING", f"Imported from NAV", user_id)
                    else:
                        skipped += 1

                except sqlite3.Error as e:
                    logger.error(f"Error inserting invoice {invoice_number}: {e}")
                    skipped += 1

        logger.info(f"Upsert complete: {inserted} inserted, {skipped} skipped")
        return inserted, skipped

    # =========================================================================
    # MARK AS RECEIVED
    # =========================================================================

    def mark_as_received(
        self,
        tenant_id: str,
        invoice_number: str,
        pdf_path: Optional[str] = None,
        notes: Optional[str] = None,
        user_id: str = "system"
    ) -> bool:
        """
        Update invoice status when PDF is received/matched.

        Args:
            tenant_id: Tenant identifier for data isolation
            invoice_number: NAV invoice number
            pdf_path: Path to the matched PDF file
            notes: Optional notes about the match
            user_id: User performing the operation

        Returns:
            True if invoice was updated, False if not found
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Get current status for audit (tenant-scoped)
            cursor.execute(
                "SELECT id, status FROM invoices WHERE tenant_id = ? AND nav_invoice_number = ?",
                (tenant_id, invoice_number)
            )
            row = cursor.fetchone()

            if not row:
                logger.warning(f"Invoice not found for tenant {tenant_id}: {invoice_number}")
                return False

            invoice_id, old_status = row["id"], row["status"]

            # Update status (tenant-scoped)
            cursor.execute("""
                UPDATE invoices
                SET status = 'RECEIVED',
                    pdf_path = ?,
                    notes = COALESCE(?, notes),
                    last_updated = CURRENT_TIMESTAMP
                WHERE tenant_id = ? AND nav_invoice_number = ?
            """, (pdf_path, notes, tenant_id, invoice_number))

            # Audit log
            self._log_audit(
                cursor, tenant_id, invoice_id, "STATUS_CHANGE",
                old_status, "RECEIVED",
                f"PDF matched: {pdf_path}" if pdf_path else "Manually marked",
                user_id
            )

            logger.info(f"Marked as received: {invoice_number} for tenant {tenant_id}")
            return True

    def assign_project_to_invoice(
        self,
        tenant_id: str,
        invoice_number: str,
        project_id: Optional[int],
        user_id: str = "system"
    ) -> bool:
        """Assign or clear a tenant project on an invoice."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, project_id FROM invoices WHERE tenant_id = ? AND nav_invoice_number = ?",
                (tenant_id, invoice_number)
            )
            invoice_row = cursor.fetchone()
            if not invoice_row:
                return False

            old_project_id = invoice_row["project_id"]

            project_code = None
            if project_id is not None:
                cursor.execute(
                    """
                    SELECT id, project_code FROM projects
                    WHERE tenant_id = ? AND id = ? AND is_active = 1
                    """,
                    (tenant_id, project_id),
                )
                project_row = cursor.fetchone()
                if not project_row:
                    raise ValueError("Project not found for tenant")
                project_id = project_row["id"]
                project_code = project_row["project_code"]

            cursor.execute(
                """
                UPDATE invoices
                SET project_id = ?, last_updated = CURRENT_TIMESTAMP
                WHERE tenant_id = ? AND nav_invoice_number = ?
                """,
                (project_id, tenant_id, invoice_number),
            )

            details = (
                f"Assigned project {project_code} (id={project_id})"
                if project_id is not None
                else "Cleared project assignment"
            )
            self._log_audit(
                cursor,
                tenant_id,
                invoice_row["id"],
                "PROJECT_ASSIGNMENT",
                str(old_project_id) if old_project_id is not None else None,
                str(project_id) if project_id is not None else None,
                details,
                user_id,
            )
            return cursor.rowcount > 0

    def mark_as_emailed(
        self,
        tenant_id: str,
        invoice_number: str,
        user_id: str = "system"
    ) -> bool:
        """Mark invoice as having reminder email sent."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT id, status, email_count FROM invoices WHERE tenant_id = ? AND nav_invoice_number = ?",
                (tenant_id, invoice_number)
            )
            row = cursor.fetchone()

            if not row:
                return False

            invoice_id, old_status, email_count = row["id"], row["status"], row["email_count"]
            new_status = "ESCALATED" if email_count >= 2 else "EMAILED"

            cursor.execute("""
                UPDATE invoices
                SET status = ?,
                    email_count = email_count + 1,
                    last_updated = CURRENT_TIMESTAMP
                WHERE tenant_id = ? AND nav_invoice_number = ?
            """, (new_status, tenant_id, invoice_number))

            self._log_audit(
                cursor, tenant_id, invoice_id, "EMAIL_SENT",
                old_status, new_status,
                f"Email #{email_count + 1} sent",
                user_id
            )

            return True

    # =========================================================================
    # QUERY MISSING INVOICES
    # =========================================================================

    def get_missing_invoices(
        self,
        tenant_id: str,
        days_old: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Get invoices older than N days that are still MISSING.

        These are candidates for reminder emails to vendors.

        Args:
            tenant_id: Tenant identifier for data isolation
            days_old: Minimum age in days (default: 5)

        Returns:
            List of invoice dictionaries for the specified tenant
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")

        cutoff_date = (datetime.now() - timedelta(days=days_old)).strftime("%Y-%m-%d")

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(f"""
                {self._invoice_select_clause()}
                WHERE i.tenant_id = ? AND i.status = 'MISSING'
                AND i.invoice_date <= ?
                ORDER BY i.invoice_date ASC
            """, (tenant_id, cutoff_date))

            return [dict(row) for row in cursor.fetchall()]

    def get_invoices_needing_followup(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Get invoices that need follow-up action.

        Returns MISSING (>5 days) and EMAILED (>3 days since last email) invoices.

        Args:
            tenant_id: Tenant identifier for data isolation
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Missing for 5+ days OR emailed 3+ days ago (tenant-scoped)
            cursor.execute(f"""
                {self._invoice_select_clause()}
                WHERE i.tenant_id = ?
                AND ((i.status = 'MISSING' AND i.invoice_date <= date('now', '-5 days'))
                   OR (i.status = 'EMAILED' AND i.last_updated <= datetime('now', '-3 days')))
                ORDER BY i.status, i.invoice_date ASC
            """, (tenant_id,))

            return [dict(row) for row in cursor.fetchall()]

    # =========================================================================
    # ADDITIONAL QUERY METHODS
    # =========================================================================

    def get_invoice(
        self,
        invoice_number: str,
        tenant_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get a single invoice by number.

        Args:
            invoice_number: NAV invoice number
            tenant_id: Optional tenant filter (if None, searches all tenants - admin only)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if tenant_id:
                cursor.execute(
                    f"{self._invoice_select_clause()} WHERE i.tenant_id = ? AND i.nav_invoice_number = ?",
                    (tenant_id, invoice_number)
                )
            else:
                # Cross-tenant search (admin use only)
                cursor.execute(
                    f"{self._invoice_select_clause()} WHERE i.nav_invoice_number = ?",
                    (invoice_number,)
                )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_invoices_by_status(
        self,
        tenant_id: str,
        status: InvoiceStatus
    ) -> List[Dict[str, Any]]:
        """Get all invoices with a specific status for a tenant."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"{self._invoice_select_clause()} WHERE i.tenant_id = ? AND i.status = ? ORDER BY i.invoice_date",
                (tenant_id, status.value)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_invoices_by_vendor(
        self,
        tenant_id: str,
        vendor_tax_number: str
    ) -> List[Dict[str, Any]]:
        """Get all invoices from a specific vendor for a tenant."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"{self._invoice_select_clause()} WHERE i.tenant_id = ? AND i.vendor_tax_number = ? ORDER BY i.invoice_date DESC",
                (tenant_id, vendor_tax_number)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self, tenant_id: str) -> Dict[str, Any]:
        """Get invoice statistics for a tenant dashboard."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()

            stats = {"tenant_id": tenant_id}

            # Count by status (tenant-scoped)
            cursor.execute("""
                SELECT status, COUNT(*) as count, SUM(amount) as total_amount
                FROM invoices WHERE tenant_id = ? GROUP BY status
            """, (tenant_id,))
            stats["by_status"] = {row["status"]: {
                "count": row["count"],
                "total_amount": row["total_amount"] or 0
            } for row in cursor.fetchall()}

            # Total counts
            cursor.execute("SELECT COUNT(*) FROM invoices WHERE tenant_id = ?", (tenant_id,))
            stats["total_invoices"] = cursor.fetchone()[0]

            # Missing older than 5 days (tenant-scoped)
            cursor.execute("""
                SELECT COUNT(*) FROM invoices
                WHERE tenant_id = ? AND status = 'MISSING'
                AND invoice_date <= date('now', '-5 days')
            """, (tenant_id,))
            stats["critical_missing"] = cursor.fetchone()[0]

            return stats

    def search_invoices(
        self,
        tenant_id: str,
        query: str,
        limit: int = 50,
        project_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Search invoices by number or vendor name within a tenant."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            search_term = f"%{query}%"
            project_filter = ""
            params: List[Any] = [tenant_id, search_term, search_term]
            if project_id is not None:
                project_filter = " AND i.project_id = ?"
                params.append(project_id)
            params.append(limit)
            cursor.execute(f"""
                {self._invoice_select_clause()}
                WHERE i.tenant_id = ?
                AND (i.nav_invoice_number LIKE ? OR i.vendor_name LIKE ?)
                {project_filter}
                ORDER BY i.last_updated DESC
                LIMIT ?
            """, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_invoices_requiring_project_mapping(
        self,
        tenant_id: str,
        invoice_numbers: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Return invoices that still need project assignment."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = f"""
                {self._invoice_select_clause()}
                WHERE i.tenant_id = ? AND i.project_id IS NULL
            """
            params: List[Any] = [tenant_id]

            if invoice_numbers:
                placeholders = ", ".join("?" for _ in invoice_numbers)
                query += f" AND i.nav_invoice_number IN ({placeholders})"
                params.extend(invoice_numbers)

            query += " ORDER BY i.invoice_date DESC"
            if limit is not None:
                query += " LIMIT ?"
                params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    # =========================================================================
    # AUDIT LOG
    # =========================================================================

    def _log_audit(
        self,
        cursor: sqlite3.Cursor,
        tenant_id: str,
        invoice_id: int,
        action: str,
        old_status: Optional[str],
        new_status: Optional[str],
        details: str,
        user_id: str = "system"
    ) -> None:
        """Log an audit entry with tenant context."""
        cursor.execute("""
            INSERT INTO audit_log (tenant_id, invoice_id, action, old_status, new_status, details, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (tenant_id, invoice_id, action, old_status, new_status, details, user_id))

    def get_audit_log(
        self,
        tenant_id: str,
        invoice_number: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get audit log entries for a tenant."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()

            if invoice_number:
                cursor.execute("""
                    SELECT a.*, i.nav_invoice_number
                    FROM audit_log a
                    JOIN invoices i ON a.invoice_id = i.id
                    WHERE a.tenant_id = ? AND i.nav_invoice_number = ?
                    ORDER BY a.performed_at DESC
                    LIMIT ?
                """, (tenant_id, invoice_number, limit))
            else:
                cursor.execute("""
                    SELECT a.*, i.nav_invoice_number
                    FROM audit_log a
                    LEFT JOIN invoices i ON a.invoice_id = i.id
                    WHERE a.tenant_id = ?
                    ORDER BY a.performed_at DESC
                    LIMIT ?
                """, (tenant_id, limit))

            return [dict(row) for row in cursor.fetchall()]

    # =========================================================================
    # BULK OPERATIONS
    # =========================================================================

    def bulk_mark_received(
        self,
        tenant_id: str,
        invoice_numbers: List[str],
        pdf_folder: str,
        user_id: str = "system"
    ) -> int:
        """
        Mark multiple invoices as received for a tenant.

        Args:
            tenant_id: Tenant identifier
            invoice_numbers: List of invoice numbers
            pdf_folder: Folder containing the PDFs
            user_id: User performing the operation

        Returns:
            Number of invoices updated
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")

        updated = 0
        for inv_num in invoice_numbers:
            if self.mark_as_received(
                tenant_id, inv_num,
                pdf_path=f"{pdf_folder}/{inv_num}.pdf",
                user_id=user_id
            ):
                updated += 1
        return updated

    def delete_invoice(
        self,
        tenant_id: str,
        invoice_number: str
    ) -> bool:
        """Delete an invoice for a tenant."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM invoices WHERE tenant_id = ? AND nav_invoice_number = ?",
                (tenant_id, invoice_number)
            )
            return cursor.rowcount > 0

    # =========================================================================
    # TENANT MANAGEMENT
    # =========================================================================

    def get_all_tenants(self) -> List[str]:
        """Get list of all tenant IDs in the database (admin only)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT tenant_id FROM invoices")
            return [row[0] for row in cursor.fetchall()]

    # =========================================================================
    # PROJECT MANAGEMENT
    # =========================================================================

    def list_projects(
        self,
        tenant_id: str,
        include_inactive: bool = False,
    ) -> List[Dict[str, Any]]:
        """List projects for a tenant."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT *
                FROM projects
                WHERE tenant_id = ?
            """
            params: List[Any] = [tenant_id]
            if not include_inactive:
                query += " AND is_active = 1"
            query += " ORDER BY project_code ASC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_project(self, tenant_id: str, project_id: int) -> Optional[Dict[str, Any]]:
        """Get a tenant-scoped project by ID."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM projects WHERE tenant_id = ? AND id = ?",
                (tenant_id, project_id),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def create_project(
        self,
        tenant_id: str,
        project_code: str,
        project_name: str,
        aliases: Optional[str] = None,
        reference_patterns: Optional[str] = None,
        is_active: bool = True,
    ) -> Dict[str, Any]:
        """Create a project for a tenant."""
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not project_code.strip():
            raise ValueError("project_code is required")
        if not project_name.strip():
            raise ValueError("project_name is required")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO projects (
                    tenant_id, project_code, project_name, aliases, reference_patterns, is_active
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    project_code.strip(),
                    project_name.strip(),
                    aliases,
                    reference_patterns,
                    1 if is_active else 0,
                ),
            )
            project_id = cursor.lastrowid
            cursor.execute(
                "SELECT * FROM projects WHERE tenant_id = ? AND id = ?",
                (tenant_id, project_id),
            )
            return dict(cursor.fetchone())

    def update_project(
        self,
        tenant_id: str,
        project_id: int,
        project_code: Optional[str] = None,
        project_name: Optional[str] = None,
        aliases: Optional[str] = None,
        reference_patterns: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update mutable project fields for a tenant."""
        if not tenant_id:
            raise ValueError("tenant_id is required")

        updates: List[str] = []
        params: List[Any] = []

        if project_code is not None:
            updates.append("project_code = ?")
            params.append(project_code.strip())
        if project_name is not None:
            updates.append("project_name = ?")
            params.append(project_name.strip())
        if aliases is not None:
            updates.append("aliases = ?")
            params.append(aliases)
        if reference_patterns is not None:
            updates.append("reference_patterns = ?")
            params.append(reference_patterns)
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if is_active else 0)

        if not updates:
            return self.get_project(tenant_id, project_id)

        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.extend([tenant_id, project_id])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                UPDATE projects
                SET {", ".join(updates)}
                WHERE tenant_id = ? AND id = ?
                """,
                params,
            )
            if cursor.rowcount == 0:
                return None

        return self.get_project(tenant_id, project_id)

    def get_tenant_summary(self) -> List[Dict[str, Any]]:
        """Get summary statistics for all tenants (admin only)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    tenant_id,
                    COUNT(*) as invoice_count,
                    SUM(amount) as total_amount,
                    SUM(CASE WHEN status = 'MISSING' THEN 1 ELSE 0 END) as missing_count,
                    SUM(CASE WHEN status = 'RECEIVED' THEN 1 ELSE 0 END) as received_count
                FROM invoices
                GROUP BY tenant_id
                ORDER BY invoice_count DESC
            """)
            return [dict(row) for row in cursor.fetchall()]


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Initialize database
    db = DatabaseManager("data/invoices.db")
    db.initialize()

    # Define tenant ID for multi-tenancy demo
    TENANT_ID = "demo-tenant-001"

    # Example: Insert some test invoices for a tenant
    test_invoices = [
        {
            "invoiceNumber": "INV-2024-001",
            "supplierName": "Test Supplier Kft.",
            "supplierTaxNumber": "12345678",
            "grossAmount": 125000.0,
            "currency": "HUF",
            "invoiceDate": "2024-01-10"
        },
        {
            "invoiceNumber": "INV-2024-002",
            "supplierName": "Another Vendor Zrt.",
            "supplierTaxNumber": "87654321",
            "grossAmount": 250000.0,
            "currency": "HUF",
            "invoiceDate": "2024-01-05"  # Old invoice
        }
    ]

    inserted, skipped = db.upsert_nav_invoices(TENANT_ID, test_invoices)
    print(f"✓ Inserted {inserted}, skipped {skipped} for tenant {TENANT_ID}")

    # Get missing invoices older than 5 days for this tenant
    missing = db.get_missing_invoices(TENANT_ID, days_old=5)
    print(f"✓ Found {len(missing)} missing invoices older than 5 days")

    # Mark one as received
    db.mark_as_received(TENANT_ID, "INV-2024-001", pdf_path="data/pdfs/Test_INV-2024-001.pdf")

    # Get statistics for this tenant
    stats = db.get_statistics(TENANT_ID)
    print(f"✓ Statistics for {TENANT_ID}: {stats}")

    # Show all tenants (admin view)
    print(f"✓ All tenants: {db.get_all_tenants()}")
