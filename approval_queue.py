"""
Email Approval Queue System

Implements human-in-the-loop workflow for AI-generated emails:
- Queue AI-generated emails for human review
- Support approval/rejection/edit workflows
- Track approval history with audit log
- Integration with email sender

Status Flow:
    PENDING → (Approve) → APPROVED → (Send) → SENT
           → (Reject)  → REJECTED
           → (Edit)    → PENDING (revised)

Requirements:
    - SQLite database for queue persistence
    - Optional: Redis for real-time notifications
"""

import os
import json
import logging
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from contextlib import contextmanager

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS
# =============================================================================

class ApprovalStatus(Enum):
    """Email approval status."""
    PENDING = "pending"       # Awaiting human review
    APPROVED = "approved"     # Approved, ready to send
    REJECTED = "rejected"     # Rejected, will not send
    SENT = "sent"             # Already sent
    EXPIRED = "expired"       # Review period expired
    EDITED = "edited"         # Content was edited before approval


class Priority(Enum):
    """Queue item priority."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class QueueItem:
    """Email in the approval queue."""
    id: str
    tenant_id: str
    invoice_number: str
    vendor_name: str
    vendor_email: str
    email_subject: str
    email_body: str
    email_tone: str
    amount: float
    invoice_date: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    priority: Priority = Priority.NORMAL
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    created_by: Optional[str] = None  # AI agent or user ID
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    original_body: Optional[str] = None  # If edited
    edit_notes: Optional[str] = None
    attempt_number: int = 1  # 1st, 2nd, 3rd reminder
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "invoice_number": self.invoice_number,
            "vendor_name": self.vendor_name,
            "vendor_email": self.vendor_email,
            "email_subject": self.email_subject,
            "email_body": self.email_body,
            "email_tone": self.email_tone,
            "amount": self.amount,
            "invoice_date": self.invoice_date,
            "status": self.status.value,
            "priority": self.priority.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_by": self.created_by,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "rejection_reason": self.rejection_reason,
            "original_body": self.original_body,
            "edit_notes": self.edit_notes,
            "attempt_number": self.attempt_number,
        }


@dataclass
class ApprovalAction:
    """Record of an approval action."""
    id: str
    queue_item_id: str
    action: str  # approve, reject, edit, send, expire
    user_id: str
    timestamp: datetime
    notes: Optional[str] = None
    old_status: Optional[str] = None
    new_status: Optional[str] = None


@dataclass
class QueueStatistics:
    """Queue statistics."""
    total: int
    pending: int
    approved: int
    rejected: int
    sent: int
    expired: int
    avg_approval_time_hours: float
    oldest_pending_hours: float


# =============================================================================
# APPROVAL QUEUE DATABASE
# =============================================================================

class ApprovalQueue:
    """
    SQLite-backed email approval queue.

    Provides human-in-the-loop workflow for AI-generated emails.

    Usage:
        queue = ApprovalQueue("data/approvals.db")
        queue.initialize()

        # Add email to queue
        item_id = queue.add_to_queue(
            tenant_id="tenant-001",
            invoice_number="INV-2024-001",
            vendor_name="Supplier Kft",
            vendor_email="contact@supplier.hu",
            email_subject="Hiányzó számla: INV-2024-001",
            email_body="Tisztelt Partner...",
            email_tone="polite",
            amount=125000,
            invoice_date="2024-01-15"
        )

        # Review and approve
        queue.approve(item_id, user_id="accountant@company.hu")

        # Get approved emails ready to send
        ready = queue.get_approved_emails()
    """

    def __init__(self, db_path: str = "data/approvals.db"):
        """Initialize the approval queue."""
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self):
        """Create database tables."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_queue (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    invoice_number TEXT NOT NULL,
                    vendor_name TEXT NOT NULL,
                    vendor_email TEXT NOT NULL,
                    email_subject TEXT NOT NULL,
                    email_body TEXT NOT NULL,
                    email_tone TEXT DEFAULT 'polite',
                    amount REAL,
                    invoice_date TEXT,
                    status TEXT DEFAULT 'pending',
                    priority INTEGER DEFAULT 2,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    created_by TEXT,
                    reviewed_by TEXT,
                    reviewed_at TIMESTAMP,
                    rejection_reason TEXT,
                    original_body TEXT,
                    edit_notes TEXT,
                    attempt_number INTEGER DEFAULT 1
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_actions (
                    id TEXT PRIMARY KEY,
                    queue_item_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT,
                    old_status TEXT,
                    new_status TEXT,
                    FOREIGN KEY (queue_item_id) REFERENCES approval_queue(id)
                )
            """)

            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_tenant ON approval_queue(tenant_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_status ON approval_queue(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_invoice ON approval_queue(invoice_number)")

            logger.info(f"Approval queue initialized at {self.db_path}")

    def add_to_queue(
        self,
        tenant_id: str,
        invoice_number: str,
        vendor_name: str,
        vendor_email: str,
        email_subject: str,
        email_body: str,
        email_tone: str = "polite",
        amount: float = 0.0,
        invoice_date: str = "",
        priority: Priority = Priority.NORMAL,
        created_by: str = "ai-agent",
        expires_hours: int = 24,
        attempt_number: int = 1
    ) -> str:
        """
        Add an AI-generated email to the approval queue.

        Args:
            tenant_id: Tenant identifier
            invoice_number: Invoice being chased
            vendor_name: Vendor name
            vendor_email: Where to send the email
            email_subject: Email subject line
            email_body: Email body content
            email_tone: Tone level (polite, firm, urgent, final)
            amount: Invoice amount
            invoice_date: Invoice date
            priority: Queue priority
            created_by: Who/what created this (ai-agent or user ID)
            expires_hours: Hours before item expires without review
            attempt_number: Which reminder attempt this is

        Returns:
            Queue item ID
        """
        item_id = f"APR-{secrets.token_hex(8)}"
        expires_at = datetime.now() + timedelta(hours=expires_hours)

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO approval_queue (
                    id, tenant_id, invoice_number, vendor_name, vendor_email,
                    email_subject, email_body, email_tone, amount, invoice_date,
                    status, priority, expires_at, created_by, attempt_number
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item_id, tenant_id, invoice_number, vendor_name, vendor_email,
                email_subject, email_body, email_tone, amount, invoice_date,
                ApprovalStatus.PENDING.value, priority.value, expires_at,
                created_by, attempt_number
            ))

            # Log action
            self._log_action(
                conn, item_id, "create", created_by,
                f"Added to queue: {invoice_number} -> {vendor_email}",
                None, ApprovalStatus.PENDING.value
            )

        logger.info(f"Added to approval queue: {item_id} for {invoice_number}")
        return item_id

    def _log_action(
        self,
        conn,
        queue_item_id: str,
        action: str,
        user_id: str,
        notes: Optional[str] = None,
        old_status: Optional[str] = None,
        new_status: Optional[str] = None
    ):
        """Log an approval action."""
        action_id = f"ACT-{secrets.token_hex(8)}"
        conn.execute("""
            INSERT INTO approval_actions (
                id, queue_item_id, action, user_id, notes, old_status, new_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (action_id, queue_item_id, action, user_id, notes, old_status, new_status))

    def get_pending_emails(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 50
    ) -> List[QueueItem]:
        """Get all pending emails awaiting approval."""
        with self._get_connection() as conn:
            if tenant_id:
                rows = conn.execute("""
                    SELECT * FROM approval_queue
                    WHERE status = 'pending' AND tenant_id = ?
                    ORDER BY priority DESC, created_at ASC
                    LIMIT ?
                """, (tenant_id, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM approval_queue
                    WHERE status = 'pending'
                    ORDER BY priority DESC, created_at ASC
                    LIMIT ?
                """, (limit,)).fetchall()

        return [self._row_to_item(row) for row in rows]

    def get_approved_emails(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 50
    ) -> List[QueueItem]:
        """Get approved emails ready to send."""
        with self._get_connection() as conn:
            if tenant_id:
                rows = conn.execute("""
                    SELECT * FROM approval_queue
                    WHERE status = 'approved' AND tenant_id = ?
                    ORDER BY priority DESC, reviewed_at ASC
                    LIMIT ?
                """, (tenant_id, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM approval_queue
                    WHERE status = 'approved'
                    ORDER BY priority DESC, created_at ASC
                    LIMIT ?
                """, (limit,)).fetchall()

        return [self._row_to_item(row) for row in rows]

    def get_item(self, item_id: str) -> Optional[QueueItem]:
        """Get a specific queue item by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM approval_queue WHERE id = ?",
                (item_id,)
            ).fetchone()

        return self._row_to_item(row) if row else None

    def approve(
        self,
        item_id: str,
        user_id: str,
        notes: Optional[str] = None
    ) -> bool:
        """
        Approve an email for sending.

        Args:
            item_id: Queue item ID
            user_id: Approver's user ID
            notes: Optional approval notes

        Returns:
            True if approved successfully
        """
        with self._get_connection() as conn:
            # Get current status
            row = conn.execute(
                "SELECT status FROM approval_queue WHERE id = ?",
                (item_id,)
            ).fetchone()

            if not row:
                logger.warning(f"Queue item not found: {item_id}")
                return False

            old_status = row["status"]

            if old_status != ApprovalStatus.PENDING.value:
                logger.warning(f"Cannot approve item with status: {old_status}")
                return False

            # Update status
            conn.execute("""
                UPDATE approval_queue
                SET status = ?, reviewed_by = ?, reviewed_at = ?, updated_at = ?
                WHERE id = ?
            """, (
                ApprovalStatus.APPROVED.value,
                user_id,
                datetime.now(),
                datetime.now(),
                item_id
            ))

            # Log action
            self._log_action(
                conn, item_id, "approve", user_id, notes,
                old_status, ApprovalStatus.APPROVED.value
            )

        logger.info(f"Email approved: {item_id} by {user_id}")
        return True

    def reject(
        self,
        item_id: str,
        user_id: str,
        reason: str
    ) -> bool:
        """
        Reject an email (will not be sent).

        Args:
            item_id: Queue item ID
            user_id: Rejector's user ID
            reason: Rejection reason (required)

        Returns:
            True if rejected successfully
        """
        if not reason or len(reason.strip()) < 5:
            logger.warning("Rejection reason is required")
            return False

        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT status FROM approval_queue WHERE id = ?",
                (item_id,)
            ).fetchone()

            if not row:
                return False

            old_status = row["status"]

            conn.execute("""
                UPDATE approval_queue
                SET status = ?, reviewed_by = ?, reviewed_at = ?,
                    rejection_reason = ?, updated_at = ?
                WHERE id = ?
            """, (
                ApprovalStatus.REJECTED.value,
                user_id,
                datetime.now(),
                reason,
                datetime.now(),
                item_id
            ))

            self._log_action(
                conn, item_id, "reject", user_id, reason,
                old_status, ApprovalStatus.REJECTED.value
            )

        logger.info(f"Email rejected: {item_id} by {user_id}: {reason}")
        return True

    def edit_and_approve(
        self,
        item_id: str,
        user_id: str,
        new_subject: Optional[str] = None,
        new_body: Optional[str] = None,
        notes: Optional[str] = None
    ) -> bool:
        """
        Edit email content and approve.

        Stores original content for audit trail.

        Args:
            item_id: Queue item ID
            user_id: Editor's user ID
            new_subject: New subject (optional)
            new_body: New body content (optional)
            notes: Edit notes

        Returns:
            True if edited and approved
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM approval_queue WHERE id = ?",
                (item_id,)
            ).fetchone()

            if not row:
                return False

            old_status = row["status"]

            # Build update fields
            updates = ["status = ?", "reviewed_by = ?", "reviewed_at = ?", "updated_at = ?"]
            values = [ApprovalStatus.APPROVED.value, user_id, datetime.now(), datetime.now()]

            # Store original if editing
            if new_body and not row["original_body"]:
                updates.append("original_body = ?")
                values.append(row["email_body"])

            if new_subject:
                updates.append("email_subject = ?")
                values.append(new_subject)

            if new_body:
                updates.append("email_body = ?")
                values.append(new_body)

            if notes:
                updates.append("edit_notes = ?")
                values.append(notes)

            values.append(item_id)

            conn.execute(f"""
                UPDATE approval_queue
                SET {', '.join(updates)}
                WHERE id = ?
            """, values)

            self._log_action(
                conn, item_id, "edit_approve", user_id, notes,
                old_status, ApprovalStatus.APPROVED.value
            )

        logger.info(f"Email edited and approved: {item_id} by {user_id}")
        return True

    def mark_as_sent(self, item_id: str, user_id: str = "system") -> bool:
        """Mark an approved email as sent."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT status FROM approval_queue WHERE id = ?",
                (item_id,)
            ).fetchone()

            if not row or row["status"] != ApprovalStatus.APPROVED.value:
                return False

            conn.execute("""
                UPDATE approval_queue
                SET status = ?, updated_at = ?
                WHERE id = ?
            """, (ApprovalStatus.SENT.value, datetime.now(), item_id))

            self._log_action(
                conn, item_id, "send", user_id, None,
                ApprovalStatus.APPROVED.value, ApprovalStatus.SENT.value
            )

        return True

    def expire_old_items(self) -> int:
        """Expire items past their expiration time. Returns count expired."""
        with self._get_connection() as conn:
            now = datetime.now()

            # Get items to expire
            rows = conn.execute("""
                SELECT id FROM approval_queue
                WHERE status = 'pending' AND expires_at < ?
            """, (now,)).fetchall()

            for row in rows:
                conn.execute("""
                    UPDATE approval_queue
                    SET status = ?, updated_at = ?
                    WHERE id = ?
                """, (ApprovalStatus.EXPIRED.value, now, row["id"]))

                self._log_action(
                    conn, row["id"], "expire", "system", "Auto-expired",
                    ApprovalStatus.PENDING.value, ApprovalStatus.EXPIRED.value
                )

        logger.info(f"Expired {len(rows)} queue items")
        return len(rows)

    def get_statistics(self, tenant_id: Optional[str] = None) -> QueueStatistics:
        """Get queue statistics."""
        with self._get_connection() as conn:
            where = "WHERE tenant_id = ?" if tenant_id else ""
            params = (tenant_id,) if tenant_id else ()

            # Get counts by status
            total = conn.execute(
                f"SELECT COUNT(*) FROM approval_queue {where}", params
            ).fetchone()[0]

            pending = conn.execute(
                f"SELECT COUNT(*) FROM approval_queue {where} {'AND' if where else 'WHERE'} status = 'pending'",
                params
            ).fetchone()[0]

            approved = conn.execute(
                f"SELECT COUNT(*) FROM approval_queue {where} {'AND' if where else 'WHERE'} status = 'approved'",
                params
            ).fetchone()[0]

            rejected = conn.execute(
                f"SELECT COUNT(*) FROM approval_queue {where} {'AND' if where else 'WHERE'} status = 'rejected'",
                params
            ).fetchone()[0]

            sent = conn.execute(
                f"SELECT COUNT(*) FROM approval_queue {where} {'AND' if where else 'WHERE'} status = 'sent'",
                params
            ).fetchone()[0]

            expired = conn.execute(
                f"SELECT COUNT(*) FROM approval_queue {where} {'AND' if where else 'WHERE'} status = 'expired'",
                params
            ).fetchone()[0]

            # Average approval time
            avg_time = conn.execute("""
                SELECT AVG(
                    (julianday(reviewed_at) - julianday(created_at)) * 24
                ) FROM approval_queue
                WHERE reviewed_at IS NOT NULL
            """).fetchone()[0] or 0.0

            # Oldest pending
            oldest = conn.execute("""
                SELECT MIN(created_at) FROM approval_queue
                WHERE status = 'pending'
            """).fetchone()[0]

            oldest_hours = 0.0
            if oldest:
                oldest_dt = datetime.fromisoformat(oldest)
                oldest_hours = (datetime.now() - oldest_dt).total_seconds() / 3600

        return QueueStatistics(
            total=total,
            pending=pending,
            approved=approved,
            rejected=rejected,
            sent=sent,
            expired=expired,
            avg_approval_time_hours=round(avg_time, 2),
            oldest_pending_hours=round(oldest_hours, 2)
        )

    def get_action_history(
        self,
        item_id: str,
        limit: int = 50
    ) -> List[ApprovalAction]:
        """Get action history for a queue item."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM approval_actions
                WHERE queue_item_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (item_id, limit)).fetchall()

        return [
            ApprovalAction(
                id=row["id"],
                queue_item_id=row["queue_item_id"],
                action=row["action"],
                user_id=row["user_id"],
                timestamp=datetime.fromisoformat(row["timestamp"]) if row["timestamp"] else None,
                notes=row["notes"],
                old_status=row["old_status"],
                new_status=row["new_status"]
            )
            for row in rows
        ]

    def _row_to_item(self, row: sqlite3.Row) -> QueueItem:
        """Convert database row to QueueItem."""
        return QueueItem(
            id=row["id"],
            tenant_id=row["tenant_id"],
            invoice_number=row["invoice_number"],
            vendor_name=row["vendor_name"],
            vendor_email=row["vendor_email"],
            email_subject=row["email_subject"],
            email_body=row["email_body"],
            email_tone=row["email_tone"],
            amount=row["amount"] or 0.0,
            invoice_date=row["invoice_date"] or "",
            status=ApprovalStatus(row["status"]),
            priority=Priority(row["priority"]),
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            created_by=row["created_by"],
            reviewed_by=row["reviewed_by"],
            reviewed_at=datetime.fromisoformat(row["reviewed_at"]) if row["reviewed_at"] else None,
            rejection_reason=row["rejection_reason"],
            original_body=row["original_body"],
            edit_notes=row["edit_notes"],
            attempt_number=row["attempt_number"]
        )


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("Email Approval Queue Demo")
    print("=" * 60)

    # Initialize queue
    queue = ApprovalQueue("data/test_approvals.db")
    queue.initialize()

    # Add email to queue
    print("\n1. Adding AI-generated email to queue...")
    item_id = queue.add_to_queue(
        tenant_id="tenant-001",
        invoice_number="INV-2024-0042",
        vendor_name="Test Supplier Kft",
        vendor_email="supplier@example.hu",
        email_subject="Hiányzó számla: INV-2024-0042",
        email_body="Tisztelt Partner!\n\nNem találjuk az INV-2024-0042 számú számlát...",
        email_tone="polite",
        amount=125000,
        invoice_date="2024-01-15",
        priority=Priority.HIGH
    )
    print(f"   ✓ Created queue item: {item_id}")

    # List pending
    print("\n2. Listing pending emails...")
    pending = queue.get_pending_emails()
    print(f"   ✓ Found {len(pending)} pending emails")
    for item in pending:
        print(f"      - {item.invoice_number}: {item.email_subject}")

    # Approve
    print("\n3. Approving email...")
    success = queue.approve(item_id, user_id="accountant@company.hu", notes="Looks good")
    print(f"   ✓ Approved: {success}")

    # Get approved
    print("\n4. Getting approved emails ready to send...")
    approved = queue.get_approved_emails()
    print(f"   ✓ Found {len(approved)} approved emails")

    # Mark as sent
    print("\n5. Marking as sent...")
    queue.mark_as_sent(item_id)

    # Statistics
    print("\n6. Queue statistics...")
    stats = queue.get_statistics()
    print(f"   Total: {stats.total}")
    print(f"   Pending: {stats.pending}")
    print(f"   Approved: {stats.approved}")
    print(f"   Sent: {stats.sent}")
    print(f"   Rejected: {stats.rejected}")

    # Action history
    print("\n7. Action history...")
    history = queue.get_action_history(item_id)
    for action in history:
        print(f"   - {action.action} by {action.user_id} at {action.timestamp}")

    print("\n✓ Demo complete!")

