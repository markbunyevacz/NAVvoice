"""
PDF Invoice Scanner

Scans a local folder for PDF invoices and matches them against
the database to mark invoices as received.

Supports TWO extraction methods:
1. Filename parsing: Vendor_InvoiceNumber.pdf
2. PDF Content scanning: Extracts text and finds invoice numbers

Filename format: Vendor_InvoiceNumber.pdf
Examples:
    - TestSupplier_INV-2024-001.pdf
    - AnotherVendor_ABC123.pdf
    - Szállító Kft_SZ-2024-0042.pdf

Also supports:
    - Nested folder scanning
    - Multiple filename patterns
    - PDF text extraction for invoice number detection
    - OCR fallback for scanned documents (optional)

Requirements:
    pip install PyPDF2      # For PDF text extraction
    pip install pdf2image   # For OCR fallback (optional)
    pip install pytesseract # For OCR (optional)
"""

import os
import re
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

# PDF extraction libraries
try:
    from PyPDF2 import PdfReader
    PYPDF2_AVAILABLE = True
except ImportError:
    PdfReader = None
    PYPDF2_AVAILABLE = False
    logging.warning("PyPDF2 not installed. PDF content scanning disabled.")

try:
    import pytesseract
    from pdf2image import convert_from_path
    OCR_AVAILABLE = True
except ImportError:
    pytesseract = None
    convert_from_path = None
    OCR_AVAILABLE = False

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
    extraction_method: str = "filename"  # filename, content, ocr
    confidence: float = 1.0  # 0.0 - 1.0 confidence score
    all_invoice_numbers: List[str] = field(default_factory=list)  # All numbers found

    def __str__(self):
        method = f" [{self.extraction_method}]" if self.extraction_method != "filename" else ""
        return f"{self.filename} -> {self.invoice_number or 'NO MATCH'}{method}"


@dataclass
class ScanResult:
    """Results of a folder scan operation."""
    total_files: int
    matched: int
    unmatched: int
    errors: int
    matched_invoices: List[str]
    unmatched_files: List[str]
    content_matches: int = 0  # Matched via content scanning
    ocr_matches: int = 0      # Matched via OCR

    def __str__(self):
        return (f"Scanned {self.total_files} PDFs: "
                f"{self.matched} matched ({self.content_matches} via content, "
                f"{self.ocr_matches} via OCR), {self.unmatched} unmatched, "
                f"{self.errors} errors")


# =============================================================================
# PDF CONTENT EXTRACTOR
# =============================================================================

class PDFContentExtractor:
    """
    Extracts text and invoice numbers from PDF content.

    Supports:
    - Direct text extraction from PDF
    - OCR fallback for scanned documents
    - Multiple invoice number pattern detection
    - Hungarian and international invoice formats
    """

    # Invoice number patterns found in PDF content
    INVOICE_PATTERNS = [
        # Hungarian formats
        r'(?:Számlaszám|Számla\s+szám|Invoice\s+(?:No|Number|#))[\s:]*([A-Z]{0,3}[-/]?\d{4}[-/]?\d{2,6})',
        r'(?:SZLA|SZ|SZL)[-/]?\d{4}[-/]?\d{4,6}',
        # International formats
        r'(?:Invoice|INV|Bill)[\s#:-]*([A-Z]{0,3}\d{4,}[-/]?\d*)',
        # Generic patterns
        r'\b([A-Z]{2,4}[-/]\d{4}[-/]\d{4,6})\b',
        r'\b(INV[-/]?\d{4}[-/]?\d{3,6})\b',
        r'\b(SZ[-/]?\d{4}[-/]?\d{4,6})\b',
        # NAV-compatible format
        r'\b(\d{8}[-/]\d{1,5}[-/]\d{5,})\b',
    ]

    # Patterns for vendor name extraction
    VENDOR_PATTERNS = [
        r'(?:Kiállító|Eladó|Seller|Vendor|From)[\s:]*(.+?)(?:\n|Adószám|Tax)',
        r'(?:Szállító|Supplier)[\s:]*(.+?)(?:\n|Cím|Address)',
    ]

    # Patterns for amounts
    AMOUNT_PATTERNS = [
        r'(?:Összesen|Total|Fizetendő|Amount\s+Due)[\s:]*([0-9\s,.]+)\s*(?:Ft|HUF|EUR|USD)?',
        r'(?:Bruttó|Gross)[\s:]*([0-9\s,.]+)\s*(?:Ft|HUF)?',
    ]

    def __init__(self, use_ocr: bool = False):
        """
        Initialize extractor.

        Args:
            use_ocr: Enable OCR fallback for scanned documents
        """
        self.use_ocr = use_ocr and OCR_AVAILABLE
        self._compiled_invoice_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INVOICE_PATTERNS
        ]
        self._compiled_vendor_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.VENDOR_PATTERNS
        ]
        self._compiled_amount_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.AMOUNT_PATTERNS
        ]

        if not PYPDF2_AVAILABLE:
            logger.warning("PyPDF2 not available - content extraction disabled")

    def extract_text(self, pdf_path: Path) -> Tuple[str, str]:
        """
        Extract text content from PDF.

        Args:
            pdf_path: Path to PDF file

        Returns:
            Tuple of (text_content, extraction_method)
        """
        text = ""
        method = "none"

        # Try PyPDF2 first
        if PYPDF2_AVAILABLE:
            try:
                reader = PdfReader(str(pdf_path))
                for page in reader.pages:
                    page_text = page.extract_text() or ""
                    text += page_text + "\n"

                if text.strip():
                    method = "pypdf2"
                    logger.debug(f"Extracted {len(text)} chars from {pdf_path.name}")

            except Exception as e:
                logger.warning(f"PyPDF2 extraction failed for {pdf_path.name}: {e}")

        # Fall back to OCR if enabled and text extraction failed
        if not text.strip() and self.use_ocr:
            try:
                text = self._extract_with_ocr(pdf_path)
                if text.strip():
                    method = "ocr"
                    logger.debug(f"OCR extracted {len(text)} chars from {pdf_path.name}")
            except Exception as e:
                logger.warning(f"OCR extraction failed for {pdf_path.name}: {e}")

        return text, method

    def _extract_with_ocr(self, pdf_path: Path) -> str:
        """Extract text using OCR (requires tesseract)."""
        if not OCR_AVAILABLE:
            return ""

        text_parts = []
        images = convert_from_path(str(pdf_path), dpi=200)

        for i, image in enumerate(images):
            page_text = pytesseract.image_to_string(image, lang='hun+eng')
            text_parts.append(page_text)
            logger.debug(f"OCR page {i+1}: {len(page_text)} chars")

        return "\n".join(text_parts)

    def find_invoice_numbers(self, text: str) -> List[Tuple[str, float]]:
        """
        Find all invoice numbers in text.

        Args:
            text: Extracted PDF text

        Returns:
            List of (invoice_number, confidence) tuples
        """
        found: Dict[str, float] = {}

        for i, pattern in enumerate(self._compiled_invoice_patterns):
            matches = pattern.findall(text)
            for match in matches:
                # Clean up the match
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[-1]
                match = match.strip().upper()

                # Validate: should have at least 4 chars and contain digits
                if len(match) >= 4 and re.search(r'\d', match):
                    # Earlier patterns have higher confidence
                    confidence = 1.0 - (i * 0.1)
                    if match not in found or found[match] < confidence:
                        found[match] = confidence

        # Sort by confidence
        return sorted(found.items(), key=lambda x: x[1], reverse=True)

    def find_vendor_name(self, text: str) -> Optional[str]:
        """Extract vendor name from PDF text."""
        for pattern in self._compiled_vendor_patterns:
            match = pattern.search(text)
            if match:
                vendor = match.group(1).strip()
                # Clean up vendor name
                vendor = re.sub(r'\s+', ' ', vendor)
                vendor = vendor[:100]  # Limit length
                return vendor
        return None

    def find_amount(self, text: str) -> Optional[float]:
        """Extract invoice amount from PDF text."""
        for pattern in self._compiled_amount_patterns:
            match = pattern.search(text)
            if match:
                amount_str = match.group(1)
                # Clean and parse
                amount_str = re.sub(r'[\s,]', '', amount_str)
                amount_str = amount_str.replace('.', '')  # Hungarian thousands separator
                try:
                    return float(amount_str)
                except ValueError:
                    continue
        return None

    def extract_invoice_data(
        self,
        pdf_path: Path
    ) -> Dict[str, any]:
        """
        Extract all invoice data from PDF.

        Returns:
            Dictionary with invoice_numbers, vendor, amount, extraction_method
        """
        text, method = self.extract_text(pdf_path)

        if not text.strip():
            return {
                "invoice_numbers": [],
                "vendor": None,
                "amount": None,
                "extraction_method": "none",
                "text_preview": "",
            }

        invoice_numbers = self.find_invoice_numbers(text)
        vendor = self.find_vendor_name(text)
        amount = self.find_amount(text)

        return {
            "invoice_numbers": invoice_numbers,
            "vendor": vendor,
            "amount": amount,
            "extraction_method": method,
            "text_preview": text[:500],  # First 500 chars for debugging
        }


# =============================================================================
# PDF SCANNER
# =============================================================================

class PDFScanner:
    """
    Scans PDF files and extracts invoice numbers.

    Two extraction methods:
    1. Filename parsing: Vendor_InvoiceNumber.pdf
    2. Content scanning: Extract text from PDF and find invoice numbers

    Supports multiple filename patterns:
    - Standard: Vendor_InvoiceNumber.pdf
    - With spaces: "Vendor Name_INV-001.pdf"
    - Date prefix: 2024-01-15_Vendor_INV-001.pdf
    - Hungarian: Szállító_SZ-2024-0001.pdf

    Usage:
        scanner = PDFScanner(db_manager, scan_content=True)
        result = scanner.scan_folder("data/pdfs/")
        print(f"Matched {result.matched} invoices ({result.content_matches} via content)")
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

    def __init__(
        self,
        db: DatabaseManager,
        scan_content: bool = True,
        use_ocr: bool = False
    ):
        """
        Initialize scanner with database connection.

        Args:
            db: DatabaseManager instance
            scan_content: Enable PDF content scanning (requires PyPDF2)
            use_ocr: Enable OCR for scanned documents (requires tesseract)
        """
        self.db = db
        self.scan_content = scan_content and PYPDF2_AVAILABLE
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.FILENAME_PATTERNS
        ]

        # Initialize content extractor if enabled
        self.content_extractor = None
        if self.scan_content:
            self.content_extractor = PDFContentExtractor(use_ocr=use_ocr)
            logger.info("PDF content scanning enabled")

    def scan_folder(
        self,
        folder_path: str,
        tenant_id: str,
        recursive: bool = True,
        dry_run: bool = False,
        content_fallback: bool = True
    ) -> ScanResult:
        """
        Scan folder for PDF files and match against database.

        Strategy:
        1. Try filename parsing first (fastest)
        2. If no match and content_fallback=True, scan PDF content

        Args:
            folder_path: Path to folder containing PDFs
            tenant_id: Tenant identifier for multi-tenancy (required)
            recursive: Scan subdirectories
            dry_run: If True, don't update database
            content_fallback: Scan content if filename doesn't match

        Returns:
            ScanResult with match statistics

        Raises:
            ValueError: If tenant_id is not provided
        """
        if not tenant_id:
            raise ValueError("tenant_id is required for multi-tenant isolation")
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
        content_matches = 0
        ocr_matches = 0

        for pdf_path in pdf_files:
            try:
                # Step 1: Try filename parsing
                scanned = self._parse_filename(pdf_path)
                matched_in_db = False

                if scanned.invoice_number:
                    invoice = self.db.get_invoice(scanned.invoice_number)
                    if invoice:
                        matched_in_db = True

                # Step 2: Content fallback if filename didn't match DB
                if not matched_in_db and content_fallback and self.content_extractor:
                    scanned = self._scan_content(pdf_path, scanned)

                    if scanned.invoice_number:
                        invoice = self.db.get_invoice(scanned.invoice_number)
                        if invoice:
                            matched_in_db = True
                            if scanned.extraction_method == "ocr":
                                ocr_matches += 1
                            else:
                                content_matches += 1

                # Step 3: Update database if matched
                if matched_in_db:
                    if not dry_run:
                        self.db.mark_as_received(
                            tenant_id=tenant_id,
                            invoice_number=scanned.invoice_number,
                            pdf_path=str(pdf_path)
                        )
                    matched_invoices.append(scanned.invoice_number)
                    logger.info(f"✓ Matched: {scanned}")
                else:
                    unmatched_files.append(str(pdf_path))
                    if scanned.invoice_number:
                        logger.debug(f"✗ Invoice not in DB: {scanned}")
                    else:
                        logger.debug(f"✗ Could not extract invoice: {pdf_path.name}")

            except Exception as e:
                logger.error(f"Error processing {pdf_path}: {e}")
                errors += 1

        return ScanResult(
            total_files=len(pdf_files),
            matched=len(matched_invoices),
            unmatched=len(unmatched_files),
            errors=errors,
            matched_invoices=matched_invoices,
            unmatched_files=unmatched_files,
            content_matches=content_matches,
            ocr_matches=ocr_matches
        )

    def _scan_content(self, pdf_path: Path, scanned: ScannedPDF) -> ScannedPDF:
        """
        Scan PDF content to find invoice numbers.

        Args:
            pdf_path: Path to PDF file
            scanned: Existing ScannedPDF from filename parsing

        Returns:
            Updated ScannedPDF with content-extracted data
        """
        if not self.content_extractor:
            return scanned

        try:
            data = self.content_extractor.extract_invoice_data(pdf_path)

            if data["invoice_numbers"]:
                # Try each found invoice number against database
                for inv_num, confidence in data["invoice_numbers"]:
                    # Check if this invoice exists in database
                    if self.db.get_invoice(inv_num):
                        return ScannedPDF(
                            filepath=pdf_path,
                            filename=pdf_path.name,
                            vendor_name=data.get("vendor") or scanned.vendor_name,
                            invoice_number=inv_num,
                            matched=True,
                            extraction_method=data["extraction_method"],
                            confidence=confidence,
                            all_invoice_numbers=[n for n, _ in data["invoice_numbers"]]
                        )

                # If none matched DB, return first found (might be new invoice)
                inv_num, confidence = data["invoice_numbers"][0]
                return ScannedPDF(
                    filepath=pdf_path,
                    filename=pdf_path.name,
                    vendor_name=data.get("vendor") or scanned.vendor_name,
                    invoice_number=inv_num,
                    matched=False,
                    extraction_method=data["extraction_method"],
                    confidence=confidence,
                    all_invoice_numbers=[n for n, _ in data["invoice_numbers"]]
                )

        except Exception as e:
            logger.warning(f"Content extraction failed for {pdf_path.name}: {e}")

        return scanned

    def scan_single_pdf(self, pdf_path: Path) -> ScannedPDF:
        """
        Scan a single PDF file with both methods.

        Args:
            pdf_path: Path to PDF file

        Returns:
            ScannedPDF with best extraction result
        """
        # Try filename first
        scanned = self._parse_filename(pdf_path)

        # Then try content if filename didn't work or for validation
        if self.content_extractor:
            scanned = self._scan_content(pdf_path, scanned)

        return scanned

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

    def __init__(self, scanner: PDFScanner, folder: str, tenant_id: str):
        """
        Initialize PDF watcher.

        Args:
            scanner: PDFScanner instance
            folder: Folder to watch
            tenant_id: Tenant identifier for multi-tenancy
        """
        self.scanner = scanner
        self.folder = folder
        self.tenant_id = tenant_id
        self._running = False

    def start(self):
        """Start watching folder for changes."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            logger.error("watchdog not installed. Run: pip install watchdog")
            return

        watcher_tenant_id = self.tenant_id

        class PDFHandler(FileSystemEventHandler):
            def __init__(self, scanner, tenant_id):
                self.scanner = scanner
                self.tenant_id = tenant_id

            def on_created(self, event):
                if event.src_path.lower().endswith('.pdf'):
                    logger.info(f"New PDF detected: {event.src_path}")
                    self.scanner.scan_folder(
                        str(Path(event.src_path).parent),
                        tenant_id=self.tenant_id,
                        recursive=False
                    )

        observer = Observer()
        observer.schedule(PDFHandler(self.scanner, watcher_tenant_id), self.folder, recursive=True)
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
        "-t", "--tenant-id",
        required=True,
        help="Tenant identifier for multi-tenancy (required)"
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
        watcher = PDFWatcher(scanner, args.folder, args.tenant_id)
        watcher.start()
    else:
        # One-time scan
        try:
            result = scanner.scan_folder(
                args.folder,
                tenant_id=args.tenant_id,
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

