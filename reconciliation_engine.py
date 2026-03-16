"""
Reconciliation Engine – NAV Invoice Sync and Chasing Pipeline

Orchestrates the full reconciliation workflow:
1. NavClient.query_incoming_invoices() → fetch NAV digest
2. DatabaseManager.upsert_nav_invoices() → persist to DB
3. PDFScanner.scan_folder() → match PDFs, mark RECEIVED
4. For MISSING items → InvoiceAgent.generate_chasing_email()
   → ApprovalQueue.add_to_queue()

MVP: run_reconciliation(tenant_id, config) triggered by FastAPI endpoint.
Phase 2: APScheduler or Celery Beat wrapper.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from nav_client import NavClient, NavCredentials, NavApiError
from database_manager import DatabaseManager
from pdf_scanner import PDFScanner
from invoice_agent import InvoiceAgent, AgentConfig, VendorDirectory, EmailTone
from approval_queue import ApprovalQueue
from project_mapper import ProjectMapper, ProjectMapperConfig

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class ReconciliationConfig:
    """Configuration for a single reconciliation run."""
    date_from: str  # YYYY-MM-DD
    date_to: str    # YYYY-MM-DD
    pdf_folder_path: str
    nav_credentials: NavCredentials
    days_old: int = 0  # Minimum age (days) for MISSING to trigger chasing
    db_path: str = "data/invoices.db"
    approval_queue_path: str = "data/approvals.db"
    agent_config: Optional[AgentConfig] = None
    project_mapper_config: Optional[ProjectMapperConfig] = None
    vendor_directory: Optional[VendorDirectory] = None
    use_test_nav_api: bool = True
    project_mapping_limit: int = 25
    prevalidation_limit: int = 25


# =============================================================================
# NAV DIGEST MAPPING
# =============================================================================

def map_nav_digest_to_upsert(
    digest_list: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Convert NAV digest format to DatabaseManager.upsert_nav_invoices format.

    NAV digest: invoiceNumber, supplierName, supplierTaxNumber,
    invoiceIssueDate, currency, invoiceNetAmountHUF, invoiceVatAmountHUF.
    """
    result = []
    for d in digest_list:
        invoice_number = d.get("invoiceNumber", "")
        if not invoice_number:
            continue

        # Gross amount = net + VAT (HUF)
        net = float(d.get("invoiceNetAmountHUF", 0) or 0)
        vat = float(d.get("invoiceVatAmountHUF", 0) or 0)
        amount = net + vat

        result.append({
            "nav_invoice_number": invoice_number,
            "invoiceNumber": invoice_number,
            "vendor_name": d.get("supplierName", "Unknown"),
            "supplierName": d.get("supplierName", "Unknown"),
            "vendor_tax_number": d.get("supplierTaxNumber", ""),
            "supplierTaxNumber": d.get("supplierTaxNumber", ""),
            "amount": amount,
            "grossAmount": amount,
            "currency": d.get("currency", "HUF"),
            "invoice_date": d.get("invoiceIssueDate", ""),
            "invoiceDate": d.get("invoiceIssueDate", ""),
        })
    return result


# =============================================================================
# MAIN PIPELINE
# =============================================================================

def run_reconciliation(
    tenant_id: str,
    config: ReconciliationConfig,
    user_id: str = "reconciliation-engine"
) -> Dict[str, Any]:
    """
    Execute the full reconciliation pipeline for a tenant.

    Steps:
    1. Query NAV for incoming invoices
    2. Upsert to database
    3. Scan PDF folder, match and mark RECEIVED
    4. For each MISSING invoice: generate AI email, add to approval queue

    Args:
        tenant_id: Tenant identifier for data isolation
        config: Reconciliation configuration
        user_id: User/system identifier for audit

    Returns:
        Summary dict with counts: nav_fetched, inserted, skipped, matched,
        missing, emails_generated, queue_added, errors
    """
    summary: Dict[str, Any] = {
        "nav_fetched": 0,
        "inserted": 0,
        "skipped": 0,
        "validation_attempted": 0,
        "warnings_detected": 0,
        "warnings_persisted": 0,
        "warning_invoices": [],
        "project_mapping_attempted": 0,
        "project_mapping_assigned": 0,
        "project_mapping_unmatched": 0,
        "matched": 0,
        "missing_count": 0,
        "emails_generated": 0,
        "queue_added": 0,
        "errors": [],
    }

    db = DatabaseManager(config.db_path)
    db.initialize()

    # -------------------------------------------------------------------------
    # Step 1: NAV query
    # -------------------------------------------------------------------------
    try:
        nav_client = NavClient(config.nav_credentials, use_test_api=config.use_test_nav_api)
        digest_list = nav_client.query_incoming_invoices(
            issue_date_from=config.date_from,
            issue_date_to=config.date_to
        )
        summary["nav_fetched"] = len(digest_list)
    except NavApiError as e:
        summary["errors"].append(f"NAV API error: {e.code} - {e.message}")
        logger.error(f"NAV query failed for tenant {tenant_id}: {e}")
        return summary
    except Exception as e:
        summary["errors"].append(f"NAV query failed: {str(e)}")
        logger.exception(f"NAV query failed for tenant {tenant_id}")
        return summary

    if not digest_list:
        logger.info(f"No NAV invoices for tenant {tenant_id} in {config.date_from}..{config.date_to}")
        return summary

    # -------------------------------------------------------------------------
    # Step 2: Map and upsert
    # -------------------------------------------------------------------------
    mapped = map_nav_digest_to_upsert(digest_list)
    inserted, skipped = db.upsert_nav_invoices(tenant_id, mapped, user_id=user_id)
    summary["inserted"] = inserted
    summary["skipped"] = skipped
    invoice_numbers = [invoice["nav_invoice_number"] for invoice in mapped]
    validated_invoice_numbers = set()
    warning_invoice_numbers = set()

    def persist_validation_findings(invoice_number: str, full_invoice: Dict[str, Any]) -> None:
        if not isinstance(full_invoice, dict):
            return
        warnings = full_invoice.get("validation_warnings")
        if not isinstance(warnings, list):
            return
        summary["validation_attempted"] += 1
        summary["warnings_detected"] += len(warnings)
        persisted = db.replace_invoice_validation_warnings(
            tenant_id=tenant_id,
            invoice_number=invoice_number,
            warnings=warnings,
            user_id=user_id,
        )
        summary["warnings_persisted"] += persisted
        validated_invoice_numbers.add(invoice_number)
        if persisted:
            warning_invoice_numbers.add(invoice_number)

    # -------------------------------------------------------------------------
    # Step 2b: Best-effort project mapping from full invoice data
    # -------------------------------------------------------------------------
    try:
        projects = db.list_projects(tenant_id, include_inactive=False)
        if projects:
            project_mapper = ProjectMapper(config=config.project_mapper_config)
            pending_mapping = db.get_invoices_requiring_project_mapping(
                tenant_id,
                invoice_numbers=invoice_numbers,
                limit=config.project_mapping_limit,
            )

            for invoice_row in pending_mapping:
                invoice_number = invoice_row["nav_invoice_number"]
                summary["project_mapping_attempted"] += 1
                try:
                    full_invoice = nav_client.query_invoice_data(
                        invoice_number,
                        validate_sept_2025=True,
                    )
                    persist_validation_findings(invoice_number, full_invoice)
                    line_descriptions = full_invoice.get("line_descriptions") or [
                        line.get("lineDescription", "")
                        for line in full_invoice.get("invoice_lines", [])
                    ]
                    match = project_mapper.map_invoice_lines(line_descriptions, projects)
                    if match.matched and match.project_id is not None:
                        db.assign_project_to_invoice(
                            tenant_id=tenant_id,
                            invoice_number=invoice_number,
                            project_id=match.project_id,
                            user_id=user_id,
                        )
                        summary["project_mapping_assigned"] += 1
                    else:
                        summary["project_mapping_unmatched"] += 1
                except NavApiError as exc:
                    summary["errors"].append(
                        f"Project mapping NAV data fetch failed for {invoice_number}: {exc.code}"
                    )
                except Exception as exc:
                    summary["errors"].append(
                        f"Project mapping failed for {invoice_number}: {str(exc)}"
                    )
                    logger.exception("Project mapping failed for %s", invoice_number)
    except Exception as exc:
        summary["errors"].append(f"Project mapping setup failed: {str(exc)}")
        logger.exception("Project mapping setup failed for tenant %s", tenant_id)

    # -------------------------------------------------------------------------
    # Step 2c: Bounded pre-validation pass for remaining invoices
    # -------------------------------------------------------------------------
    remaining_validation_slots = max(
        config.prevalidation_limit - len(validated_invoice_numbers),
        0,
    )
    for invoice_number in invoice_numbers:
        if remaining_validation_slots <= 0:
            break
        if invoice_number in validated_invoice_numbers:
            continue
        try:
            full_invoice = nav_client.query_invoice_data(
                invoice_number,
                validate_sept_2025=True,
            )
            persist_validation_findings(invoice_number, full_invoice)
            remaining_validation_slots -= 1
        except NavApiError as exc:
            summary["errors"].append(
                f"Pre-validation NAV data fetch failed for {invoice_number}: {exc.code}"
            )
        except Exception as exc:
            summary["errors"].append(
                f"Pre-validation failed for {invoice_number}: {str(exc)}"
            )
            logger.exception("Pre-validation failed for %s", invoice_number)

    summary["warning_invoices"] = sorted(warning_invoice_numbers)

    # -------------------------------------------------------------------------
    # Step 3: PDF scan (match and mark RECEIVED)
    # -------------------------------------------------------------------------
    try:
        scanner = PDFScanner(db, scan_content=True, enable_malware_scan=True)
        scan_result = scanner.scan_folder(
            config.pdf_folder_path,
            tenant_id,
            recursive=True,
            dry_run=False
        )
        summary["matched"] = scan_result.matched
    except FileNotFoundError:
        logger.warning(
            "PDF folder not found for tenant %s: %s",
            tenant_id, config.pdf_folder_path
        )
        summary["errors"].append(f"PDF folder not found: {config.pdf_folder_path}")
    except Exception as e:
        summary["errors"].append(f"PDF scan failed: {str(e)}")
        logger.exception(f"PDF scan failed for tenant {tenant_id}")

    # -------------------------------------------------------------------------
    # Step 4: MISSING invoices → AI email → ApprovalQueue
    # -------------------------------------------------------------------------
    missing = db.get_missing_invoices(tenant_id, days_old=config.days_old)
    summary["missing_count"] = len(missing)

    if not missing:
        logger.info(f"No MISSING invoices for tenant {tenant_id}")
        return summary

    vendor_dir = config.vendor_directory or VendorDirectory()
    agent_config = config.agent_config
    approval_queue = ApprovalQueue(config.approval_queue_path)
    approval_queue.initialize()

    for inv in missing:
        invoice_number = inv.get("nav_invoice_number", "")
        vendor_name = inv.get("vendor_name", "Unknown")
        vendor_tax = inv.get("vendor_tax_number", "") or ""
        amount = float(inv.get("amount", 0) or 0)
        invoice_date = inv.get("invoice_date", "")

        # Generate AI email
        if agent_config:
            try:
                agent = InvoiceAgent(agent_config)
                result = agent.generate_chasing_email(
                    vendor=vendor_name,
                    invoice_num=invoice_number,
                    amount=amount,
                    date=invoice_date,
                    tone=EmailTone.POLITE,
                )
                if result.get("success"):
                    email_subject = result["email_subject"]
                    email_body = result["email_body"]
                    email_tone = "polite"
                    summary["emails_generated"] += 1
                else:
                    logger.warning(
                        "AI email generation failed for %s: %s",
                        invoice_number, result.get("error")
                    )
                    continue
            except Exception:
                logger.exception("InvoiceAgent failed for %s", invoice_number)
                continue
        else:
            # Fallback: minimal template without AI
            email_subject = f"Hiányzó számla - {invoice_number}"
            email_body = (
                f"Tisztelt Partnerünk!\n\n"
                f"Kérjük, küldjék el a {invoice_number} számú számlát.\n"
                f"Összeg: {amount} Ft, dátum: {invoice_date}.\n\n"
                f"Üdvözlettel,\nPénzügyi Osztály"
            )
            email_tone = "polite"

        # Vendor email lookup
        vendor_email = vendor_dir.get_email(vendor_name, tax_number=vendor_tax or None)
        if not vendor_email:
            vendor_email = f"pending-lookup@{tenant_id}.local"
            logger.info(f"No vendor email for {vendor_name}, using placeholder")

        # Add to approval queue
        try:
            approval_queue.add_to_queue(
                tenant_id=tenant_id,
                invoice_number=invoice_number,
                vendor_name=vendor_name,
                vendor_email=vendor_email,
                email_subject=email_subject,
                email_body=email_body,
                email_tone=email_tone,
                amount=amount,
                invoice_date=invoice_date,
                created_by=user_id,
                attempt_number=(inv.get("email_count", 0) + 1),
            )
            summary["queue_added"] += 1
        except Exception as e:
            logger.exception(f"Failed to add {invoice_number} to approval queue")
            summary["errors"].append(f"Queue add failed for {invoice_number}: {str(e)}")

    logger.info(
        "Reconciliation complete for %s: nav=%s, inserted=%s, matched=%s, "
        "queue_added=%s",
        tenant_id,
        summary["nav_fetched"],
        summary["inserted"],
        summary["matched"],
        summary["queue_added"],
    )
    return summary
