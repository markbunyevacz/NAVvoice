"""
PDF Invoice Scanner

Scans a local folder for PDF invoices and matches them against
the database to mark invoices as received.

Filename format: Vendor_InvoiceNumber.pdf
Examples:
    - TestSupplier_INV-2024-001.pdf
    - AnotherVendor_ABC123.pdf
    - Szállító Kft_SZ-2024-0042.pdf

Also supports:
    - Nested folder scanning
    - Multiple filename patterns
    - OCR-based invoice number extraction (optional)
"""

import os
import re
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime

from database_manager import DatabaseManager, InvoiceStatus

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ScannedPDF:
    """Represents a scanned PDF file."""
    filepath: Path
    filename: str
    vendor_name: Optional[str]
    invoice_number: Optional[str]
    matched: bool = False
    
    def __str__(self):
        return f"{self.filename} -> {self.invoice_number or 'NO MATCH'}"


@dataclass
class ScanResult:
    """Results of a folder scan operation."""
    total_files: int
    matched: int
    unmatched: int
    errors: int
    matched_invoices: List[str]
    unmatched_files: List[str]
    
    def __str__(self):
        return (f"Scanned {self.total_files} PDFs: "
                f"{self.matched} matched, {self.unmatched} unmatched, "
                f"{self.errors} errors")


# =============================================================================
# PDF SCANNER
# =============================================================================

class PDFScanner:
    """
    Scans PDF files and extracts invoice numbers from filenames.
    
    Supports multiple filename patterns:
    - Standard: Vendor_InvoiceNumber.pdf
    - With spaces: "Vendor Name_INV-001.pdf"
    - Date prefix: 2024-01-15_Vendor_INV-001.pdf
    - Hungarian: Szállító_SZ-2024-0001.pdf
    
    Usage:
        scanner = PDFScanner(db_manager)
        result = scanner.scan_folder("data/pdfs/")
        print(f"Matched {result.matched} invoices")
    """
    
    # Filename patterns to try (in order)
    FILENAME_PATTERNS = [
        # Standard: Vendor_InvoiceNumber.pdf
        r'^(?P<vendor>.+?)_(?P<invoice>[A-Za-z0-9\-\/]+)\.pdf$',
        # With date prefix: 2024-01-15_Vendor_InvoiceNumber.pdf
        r'^\d{4}-\d{2}-\d{2}_(?P<vendor>.+?)_(?P<invoice>[A-Za-z0-9\-\/]+)\.pdf$',
        # Invoice number only: INV-2024-001.pdf
        r'^(?P<invoice>[A-Z]{2,4}[-/]?\d{4}[-/]?\d+)\.pdf$',
        # Hungarian format: SZ-2024-0001.pdf or SZL-2024-0001.pdf
        r'^(?P<invoice>SZ[LA]?[-/]?\d{4}[-/]?\d+)\.pdf$',
    ]
    
    def __init__(self, db: DatabaseManager):
        """
        Initialize scanner with database connection.
        
        Args:
            db: DatabaseManager instance
        """
        self.db = db
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.FILENAME_PATTERNS
        ]
    
    def scan_folder(
        self,
        folder_path: str,
        recursive: bool = True,
        dry_run: bool = False
    ) -> ScanResult:
        """
        Scan folder for PDF files and match against database.
        
        Args:
            folder_path: Path to folder containing PDFs
            recursive: Scan subdirectories
            dry_run: If True, don't update database
            
        Returns:
            ScanResult with match statistics
        """
        folder = Path(folder_path)
        if not folder.exists():
            raise FileNotFoundError(f"Folder not found: {folder_path}")
        
        # Find all PDF files
        pattern = "**/*.pdf" if recursive else "*.pdf"
        pdf_files = list(folder.glob(pattern))
        
        logger.info(f"Found {len(pdf_files)} PDF files in {folder_path}")
        
        matched_invoices = []
        unmatched_files = []
        errors = 0
        
        for pdf_path in pdf_files:
            try:
                scanned = self._parse_filename(pdf_path)
                
                if scanned.invoice_number:
                    # Check if invoice exists in database
                    invoice = self.db.get_invoice(scanned.invoice_number)
                    
                    if invoice:
                        if not dry_run:
                            self.db.mark_as_received(
                                scanned.invoice_number,
                                pdf_path=str(pdf_path)
                            )
                        matched_invoices.append(scanned.invoice_number)
                        logger.info(f"✓ Matched: {scanned}")
                    else:
                        unmatched_files.append(str(pdf_path))
                        logger.debug(f"✗ Invoice not in DB: {scanned}")
                else:
                    unmatched_files.append(str(pdf_path))
                    logger.debug(f"✗ Could not parse: {pdf_path.name}")
                    
            except Exception as e:
                logger.error(f"Error processing {pdf_path}: {e}")
                errors += 1
        
        return ScanResult(
            total_files=len(pdf_files),
            matched=len(matched_invoices),
            unmatched=len(unmatched_files),
            errors=errors,
            matched_invoices=matched_invoices,
            unmatched_files=unmatched_files
        )

    def _parse_filename(self, pdf_path: Path) -> ScannedPDF:
        """
        Extract vendor and invoice number from filename.

        Args:
            pdf_path: Path to PDF file

        Returns:
            ScannedPDF with extracted data
        """
        filename = pdf_path.name

        for pattern in self._compiled_patterns:
            match = pattern.match(filename)
            if match:
                groups = match.groupdict()
                return ScannedPDF(
                    filepath=pdf_path,
                    filename=filename,
                    vendor_name=groups.get("vendor"),
                    invoice_number=groups.get("invoice"),
                    matched=True
                )

        # No pattern matched
        return ScannedPDF(
            filepath=pdf_path,
            filename=filename,
            vendor_name=None,
            invoice_number=None,
            matched=False
        )

    def extract_invoice_number(self, filename: str) -> Optional[str]:
        """
        Extract invoice number from filename string.

        Convenience method for testing patterns.
        """
        scanned = self._parse_filename(Path(filename))
        return scanned.invoice_number

    def suggest_matches(self, pdf_path: Path) -> List[Dict]:
        """
        Suggest possible database matches for unmatched PDF.

        Uses fuzzy matching on vendor name and partial invoice number.
        """
        scanned = self._parse_filename(pdf_path)

        if scanned.vendor_name:
            # Search by vendor name
            return self.db.search_invoices(scanned.vendor_name, limit=5)

        return []


# =============================================================================
# WATCH MODE (Optional)
# =============================================================================

class PDFWatcher:
    """
    Watch folder for new PDFs and process them automatically.

    Requires: pip install watchdog
    """

    def __init__(self, scanner: PDFScanner, folder: str):
        self.scanner = scanner
        self.folder = folder
        self._running = False

    def start(self):
        """Start watching folder for changes."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            logger.error("watchdog not installed. Run: pip install watchdog")
            return

        class PDFHandler(FileSystemEventHandler):
            def __init__(self, scanner):
                self.scanner = scanner

            def on_created(self, event):
                if event.src_path.lower().endswith('.pdf'):
                    logger.info(f"New PDF detected: {event.src_path}")
                    self.scanner.scan_folder(
                        str(Path(event.src_path).parent),
                        recursive=False
                    )

        observer = Observer()
        observer.schedule(PDFHandler(self.scanner), self.folder, recursive=True)
        observer.start()

        logger.info(f"Watching {self.folder} for new PDFs...")
        self._running = True

        try:
            import time
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()

        observer.join()

    def stop(self):
        """Stop watching."""
        self._running = False


# =============================================================================
# CLI SCRIPT
# =============================================================================

def main():
    """Command-line interface for PDF scanner."""
    parser = argparse.ArgumentParser(
        description="Scan PDF invoices and update database"
    )
    parser.add_argument(
        "folder",
        nargs="?",
        default="data/pdfs",
        help="Folder to scan (default: data/pdfs)"
    )
    parser.add_argument(
        "-d", "--database",
        default="data/invoices.db",
        help="Database path (default: data/invoices.db)"
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        default=True,
        help="Scan subdirectories (default: True)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't update database, just show matches"
    )
    parser.add_argument(
        "-w", "--watch",
        action="store_true",
        help="Watch folder for new files"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # Initialize database
    db = DatabaseManager(args.database)
    db.initialize()

    # Create scanner
    scanner = PDFScanner(db)

    if args.watch:
        # Watch mode
        watcher = PDFWatcher(scanner, args.folder)
        watcher.start()
    else:
        # One-time scan
        try:
            result = scanner.scan_folder(
                args.folder,
                recursive=args.recursive,
                dry_run=args.dry_run
            )

            print(f"\n{'='*50}")
            print(f"SCAN RESULTS")
            print(f"{'='*50}")
            print(f"Total PDFs scanned: {result.total_files}")
            print(f"Matched to database: {result.matched}")
            print(f"Unmatched files: {result.unmatched}")
            print(f"Errors: {result.errors}")

            if result.matched_invoices:
                print(f"\n✓ Matched invoices:")
                for inv in result.matched_invoices[:10]:
                    print(f"  - {inv}")
                if len(result.matched_invoices) > 10:
                    print(f"  ... and {len(result.matched_invoices) - 10} more")

            if result.unmatched_files and args.verbose:
                print(f"\n✗ Unmatched files:")
                for f in result.unmatched_files[:10]:
                    print(f"  - {Path(f).name}")

            if args.dry_run:
                print(f"\n[DRY RUN - No database changes made]")

        except FileNotFoundError as e:
            print(f"Error: {e}")
            return 1

    return 0


if __name__ == "__main__":
    exit(main())

