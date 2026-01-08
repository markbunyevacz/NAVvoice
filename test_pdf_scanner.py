"""
Comprehensive tests for the pdf_scanner.py module.

Tests cover:
- PDFMalwareScanner: malware detection patterns, file validation
- PDFContentExtractor: text extraction, invoice number detection
- PDFScanner: folder scanning, filename parsing
- ScannedPDF and ScanResult dataclasses
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

from pdf_scanner import (
    PDFMalwareScanner,
    PDFContentExtractor,
    PDFScanner,
    ScannedPDF,
    ScanResult,
)


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def malware_scanner():
    """Create malware scanner for testing."""
    return PDFMalwareScanner(strict_mode=False)


@pytest.fixture
def strict_malware_scanner():
    """Create strict mode malware scanner for testing."""
    return PDFMalwareScanner(strict_mode=True)


@pytest.fixture
def content_extractor():
    """Create content extractor for testing."""
    return PDFContentExtractor(use_ocr=False)


@pytest.fixture
def temp_pdf_dir(tmp_path):
    """Create temporary directory with test PDF files."""
    return tmp_path


@pytest.fixture
def valid_pdf_content():
    """Create valid PDF content for testing."""
    return b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF'


@pytest.fixture
def mock_db():
    """Create mock database manager."""
    db = MagicMock()
    db.get_invoice.return_value = None
    db.search_invoices.return_value = []
    return db


# =============================================================================
# PDF MALWARE SCANNER TESTS
# =============================================================================

class TestPDFMalwareScanner:
    """Tests for PDFMalwareScanner class."""

    def test_scan_valid_pdf(self, malware_scanner, temp_pdf_dir, valid_pdf_content):
        """Test scanning a valid PDF file."""
        pdf_path = temp_pdf_dir / "valid.pdf"
        pdf_path.write_bytes(valid_pdf_content)
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert is_safe is True
        assert len(warnings) == 0

    def test_scan_nonexistent_file(self, malware_scanner, temp_pdf_dir):
        """Test scanning a non-existent file."""
        pdf_path = temp_pdf_dir / "nonexistent.pdf"
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert is_safe is False
        assert "does not exist" in warnings[0]

    def test_scan_empty_file(self, malware_scanner, temp_pdf_dir):
        """Test scanning an empty file."""
        pdf_path = temp_pdf_dir / "empty.pdf"
        pdf_path.write_bytes(b'')
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert is_safe is False
        assert "empty" in warnings[0].lower()

    def test_scan_invalid_pdf_header(self, malware_scanner, temp_pdf_dir):
        """Test scanning a file with invalid PDF header."""
        pdf_path = temp_pdf_dir / "invalid.pdf"
        pdf_path.write_bytes(b'Not a PDF file content')
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert is_safe is False
        assert "Invalid PDF header" in warnings[0]

    def test_detect_javascript_high_risk(self, malware_scanner, temp_pdf_dir):
        """Test detection of JavaScript (high risk)."""
        pdf_content = b'%PDF-1.4\n/JavaScript (alert("test"))\n%%EOF'
        pdf_path = temp_pdf_dir / "js.pdf"
        pdf_path.write_bytes(pdf_content)
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert is_safe is False
        assert any("JavaScript" in w for w in warnings)
        assert any("HIGH RISK" in w for w in warnings)

    def test_detect_launch_action_high_risk(self, malware_scanner, temp_pdf_dir):
        """Test detection of Launch action (high risk)."""
        pdf_content = b'%PDF-1.4\n/Launch /Action\n%%EOF'
        pdf_path = temp_pdf_dir / "launch.pdf"
        pdf_path.write_bytes(pdf_content)
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert is_safe is False
        assert any("Launch" in w for w in warnings)

    def test_detect_embedded_file_warning(self, malware_scanner, temp_pdf_dir):
        """Test detection of embedded files (warning in non-strict mode)."""
        pdf_content = b'%PDF-1.4\n/EmbeddedFile stream\n%%EOF'
        pdf_path = temp_pdf_dir / "embedded.pdf"
        pdf_path.write_bytes(pdf_content)
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        # Non-strict mode: warning but still safe
        assert is_safe is True
        assert any("Embedded" in w for w in warnings)

    def test_strict_mode_blocks_embedded_files(self, strict_malware_scanner, temp_pdf_dir):
        """Test strict mode blocks embedded files."""
        pdf_content = b'%PDF-1.4\n/EmbeddedFile stream\n%%EOF'
        pdf_path = temp_pdf_dir / "embedded.pdf"
        pdf_path.write_bytes(pdf_content)
        
        is_safe, warnings = strict_malware_scanner.scan_file(pdf_path)
        
        assert is_safe is False
        assert any("Embedded" in w for w in warnings)

    def test_detect_uri_action(self, malware_scanner, temp_pdf_dir):
        """Test detection of URI actions."""
        pdf_content = b'%PDF-1.4\n/URI (http://malicious.com)\n%%EOF'
        pdf_path = temp_pdf_dir / "uri.pdf"
        pdf_path.write_bytes(pdf_content)
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert any("URI" in w for w in warnings)

    def test_detect_acroform(self, malware_scanner, temp_pdf_dir):
        """Test detection of AcroForm."""
        pdf_content = b'%PDF-1.4\n/AcroForm << /Fields [] >>\n%%EOF'
        pdf_path = temp_pdf_dir / "form.pdf"
        pdf_path.write_bytes(pdf_content)
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert any("AcroForm" in w for w in warnings)

    def test_detect_encryption(self, malware_scanner, temp_pdf_dir):
        """Test detection of encryption."""
        pdf_content = b'%PDF-1.4\n/Encrypt << /Filter /Standard >>\n%%EOF'
        pdf_path = temp_pdf_dir / "encrypted.pdf"
        pdf_path.write_bytes(pdf_content)
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert any("Encryption" in w for w in warnings)

    def test_detect_excessive_object_streams(self, malware_scanner, temp_pdf_dir):
        """Test detection of excessive object streams."""
        # Create content with many object streams
        obj_streams = b'/ObjStm ' * 15
        pdf_content = b'%PDF-1.4\n' + obj_streams + b'\n%%EOF'
        pdf_path = temp_pdf_dir / "obfuscated.pdf"
        pdf_path.write_bytes(pdf_content)
        
        is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert any("object streams" in w.lower() for w in warnings)

    def test_file_size_limit(self, temp_pdf_dir):
        """Test file size limit enforcement."""
        scanner = PDFMalwareScanner(strict_mode=True, max_file_size=100)
        
        # Create file larger than limit
        pdf_content = b'%PDF-1.4\n' + b'x' * 200 + b'\n%%EOF'
        pdf_path = temp_pdf_dir / "large.pdf"
        pdf_path.write_bytes(pdf_content)
        
        is_safe, warnings = scanner.scan_file(pdf_path)
        
        assert is_safe is False
        assert any("size" in w.lower() for w in warnings)

    def test_scan_batch(self, malware_scanner, temp_pdf_dir, valid_pdf_content):
        """Test batch scanning of multiple PDFs."""
        # Create multiple test files
        paths = []
        for i in range(3):
            pdf_path = temp_pdf_dir / f"test{i}.pdf"
            pdf_path.write_bytes(valid_pdf_content)
            paths.append(pdf_path)
        
        results = malware_scanner.scan_batch(paths)
        
        assert len(results) == 3
        for path_str, (is_safe, warnings) in results.items():
            assert is_safe is True

    def test_permission_error_handling(self, malware_scanner, temp_pdf_dir):
        """Test handling of permission errors."""
        pdf_path = temp_pdf_dir / "noperm.pdf"
        pdf_path.write_bytes(b'%PDF-1.4\n%%EOF')
        
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            is_safe, warnings = malware_scanner.scan_file(pdf_path)
        
        assert is_safe is False
        assert any("Permission" in w for w in warnings)


# =============================================================================
# PDF CONTENT EXTRACTOR TESTS
# =============================================================================

class TestPDFContentExtractor:
    """Tests for PDFContentExtractor class."""

    def test_find_invoice_numbers_hungarian_format(self, content_extractor):
        """Test finding Hungarian invoice numbers."""
        text = "Számlaszám: SZ-2024-0001\nÖsszesen: 100000 Ft"
        
        results = content_extractor.find_invoice_numbers(text)
        
        assert len(results) > 0
        assert any("SZ-2024-0001" in r[0] for r in results)

    def test_find_invoice_numbers_international_format(self, content_extractor):
        """Test finding international invoice numbers."""
        text = "Invoice Number: INV-2024-12345\nTotal: $1000"
        
        results = content_extractor.find_invoice_numbers(text)
        
        assert len(results) > 0
        assert any("INV-2024-12345" in r[0] for r in results)

    def test_find_invoice_numbers_nav_format(self, content_extractor):
        """Test finding NAV-compatible invoice numbers."""
        text = "Invoice: 12345678-1-12345\nAmount: 50000 HUF"
        
        results = content_extractor.find_invoice_numbers(text)
        
        assert len(results) > 0

    def test_find_invoice_numbers_multiple(self, content_extractor):
        """Test finding multiple invoice numbers in text."""
        text = """
        Invoice 1: INV-2024-001
        Invoice 2: SZ-2024-0002
        Reference: ABC-1234-5678
        """
        
        results = content_extractor.find_invoice_numbers(text)
        
        assert len(results) >= 2

    def test_find_invoice_numbers_confidence_ordering(self, content_extractor):
        """Test that results are ordered by confidence."""
        text = "Számlaszám: SZ-2024-0001\nAlso: INV-9999"
        
        results = content_extractor.find_invoice_numbers(text)
        
        if len(results) > 1:
            # First result should have higher or equal confidence
            assert results[0][1] >= results[1][1]

    def test_find_invoice_numbers_no_match(self, content_extractor):
        """Test when no invoice numbers found."""
        text = "This is just some random text without any invoice numbers."
        
        results = content_extractor.find_invoice_numbers(text)
        
        assert len(results) == 0

    def test_find_vendor_name_hungarian(self, content_extractor):
        """Test finding Hungarian vendor names."""
        text = "Kiállító: Test Kft.\nAdószám: 12345678-2-42"
        
        vendor = content_extractor.find_vendor_name(text)
        
        assert vendor is not None
        assert "Test Kft" in vendor

    def test_find_vendor_name_international(self, content_extractor):
        """Test finding international vendor names."""
        text = "Seller: ABC Company Ltd\nTax ID: 123456"
        
        vendor = content_extractor.find_vendor_name(text)
        
        assert vendor is not None
        assert "ABC Company" in vendor

    def test_find_vendor_name_not_found(self, content_extractor):
        """Test when vendor name not found."""
        text = "Just some invoice text without vendor info"
        
        vendor = content_extractor.find_vendor_name(text)
        
        assert vendor is None

    def test_find_amount_hungarian(self, content_extractor):
        """Test finding Hungarian amounts."""
        text = "Összesen: 100 000 Ft"
        
        amount = content_extractor.find_amount(text)
        
        assert amount is not None
        assert amount == 100000.0

    def test_find_amount_international(self, content_extractor):
        """Test finding international amounts."""
        text = "Total: 1,500.00 EUR"
        
        amount = content_extractor.find_amount(text)
        
        assert amount is not None

    def test_find_amount_not_found(self, content_extractor):
        """Test when amount not found."""
        text = "Invoice without amount information"
        
        amount = content_extractor.find_amount(text)
        
        assert amount is None

    @patch('pdf_scanner.PYPDF2_AVAILABLE', True)
    @patch('pdf_scanner.PdfReader')
    def test_extract_text_success(self, mock_reader, content_extractor, temp_pdf_dir):
        """Test successful text extraction."""
        # Setup mock
        mock_page = MagicMock()
        mock_page.extract_text.return_value = "Invoice: INV-2024-001"
        mock_reader_instance = MagicMock()
        mock_reader_instance.pages = [mock_page]
        mock_reader.return_value = mock_reader_instance
        
        pdf_path = temp_pdf_dir / "test.pdf"
        pdf_path.write_bytes(b'%PDF-1.4\n%%EOF')
        
        text, method = content_extractor.extract_text(pdf_path)
        
        assert "INV-2024-001" in text
        assert method == "pypdf2"

    @patch('pdf_scanner.PYPDF2_AVAILABLE', True)
    @patch('pdf_scanner.PdfReader')
    def test_extract_invoice_data(self, mock_reader, content_extractor, temp_pdf_dir):
        """Test full invoice data extraction."""
        # Setup mock
        mock_page = MagicMock()
        mock_page.extract_text.return_value = """
        Kiállító: Test Vendor Kft.
        Adószám: 12345678-2-42
        Számlaszám: SZ-2024-0001
        Összesen: 50 000 Ft
        """
        mock_reader_instance = MagicMock()
        mock_reader_instance.pages = [mock_page]
        mock_reader.return_value = mock_reader_instance
        
        pdf_path = temp_pdf_dir / "invoice.pdf"
        pdf_path.write_bytes(b'%PDF-1.4\n%%EOF')
        
        data = content_extractor.extract_invoice_data(pdf_path)
        
        assert len(data["invoice_numbers"]) > 0
        assert data["vendor"] is not None
        assert data["extraction_method"] == "pypdf2"


# =============================================================================
# PDF SCANNER TESTS
# =============================================================================

class TestPDFScanner:
    """Tests for PDFScanner class."""

    def test_parse_filename_standard(self, mock_db, temp_pdf_dir):
        """Test parsing standard filename format."""
        scanner = PDFScanner(mock_db, scan_content=False)
        
        pdf_path = temp_pdf_dir / "TestVendor_INV-2024-001.pdf"
        result = scanner._parse_filename(pdf_path)
        
        assert result is not None
        assert result.vendor_name == "TestVendor"
        assert result.invoice_number == "INV-2024-001"

    def test_parse_filename_with_spaces(self, mock_db, temp_pdf_dir):
        """Test parsing filename with spaces."""
        scanner = PDFScanner(mock_db, scan_content=False)
        
        pdf_path = temp_pdf_dir / "Test Vendor_INV-2024-001.pdf"
        result = scanner._parse_filename(pdf_path)
        
        assert result is not None
        assert result.vendor_name is not None
        assert "Test" in result.vendor_name

    def test_parse_filename_hungarian(self, mock_db, temp_pdf_dir):
        """Test parsing Hungarian filename format."""
        scanner = PDFScanner(mock_db, scan_content=False)
        
        pdf_path = temp_pdf_dir / "Szállító Kft_SZ-2024-0001.pdf"
        result = scanner._parse_filename(pdf_path)
        
        assert result is not None
        assert result.vendor_name is not None
        assert "Szállító" in result.vendor_name

    def test_parse_filename_no_match(self, mock_db, temp_pdf_dir):
        """Test parsing filename that doesn't match patterns."""
        scanner = PDFScanner(mock_db, scan_content=False)
        
        pdf_path = temp_pdf_dir / "random_file_name.pdf"
        result = scanner._parse_filename(pdf_path)
        
        # Should return a ScannedPDF object even if no match
        assert result is not None

    def test_extract_invoice_number(self, mock_db):
        """Test invoice number extraction from filename."""
        scanner = PDFScanner(mock_db, scan_content=False)
        
        number = scanner.extract_invoice_number("TestVendor_INV-2024-001.pdf")
        
        assert number == "INV-2024-001"

    @patch('pdf_scanner.PYPDF2_AVAILABLE', True)
    @patch('pdf_scanner.PdfReader')
    def test_scan_single_pdf(self, mock_reader, mock_db, temp_pdf_dir):
        """Test scanning a single PDF file."""
        # Setup mock
        mock_page = MagicMock()
        mock_page.extract_text.return_value = "Invoice: INV-2024-001"
        mock_reader_instance = MagicMock()
        mock_reader_instance.pages = [mock_page]
        mock_reader.return_value = mock_reader_instance
        
        scanner = PDFScanner(mock_db, scan_content=True, enable_malware_scan=False)
        
        pdf_path = temp_pdf_dir / "TestVendor_INV-2024-001.pdf"
        pdf_path.write_bytes(b'%PDF-1.4\n%%EOF')
        
        result = scanner.scan_single_pdf(pdf_path)
        
        assert result is not None
        # Invoice number is extracted from filename - may be partial match
        assert result.invoice_number is not None
        assert "2024-001" in result.invoice_number

    def test_scan_folder_empty(self, mock_db, temp_pdf_dir):
        """Test scanning an empty folder."""
        scanner = PDFScanner(mock_db, scan_content=False, enable_malware_scan=False)
        
        result = scanner.scan_folder(str(temp_pdf_dir))
        
        assert result.total_files == 0
        assert result.matched == 0

    def test_scan_folder_with_pdfs(self, mock_db, temp_pdf_dir):
        """Test scanning folder with PDF files."""
        scanner = PDFScanner(mock_db, scan_content=False, enable_malware_scan=False)
        
        # Create test PDFs
        (temp_pdf_dir / "Vendor1_INV-001.pdf").write_bytes(b'%PDF-1.4\n%%EOF')
        (temp_pdf_dir / "Vendor2_INV-002.pdf").write_bytes(b'%PDF-1.4\n%%EOF')
        
        result = scanner.scan_folder(str(temp_pdf_dir))
        
        assert result.total_files == 2

    def test_scan_folder_recursive(self, mock_db, temp_pdf_dir):
        """Test recursive folder scanning."""
        scanner = PDFScanner(mock_db, scan_content=False, enable_malware_scan=False)
        
        # Create nested structure
        subdir = temp_pdf_dir / "subdir"
        subdir.mkdir()
        (temp_pdf_dir / "Vendor1_INV-001.pdf").write_bytes(b'%PDF-1.4\n%%EOF')
        (subdir / "Vendor2_INV-002.pdf").write_bytes(b'%PDF-1.4\n%%EOF')
        
        result = scanner.scan_folder(str(temp_pdf_dir), recursive=True)
        
        assert result.total_files == 2

    def test_malware_scan_blocks_dangerous_pdf(self, mock_db, temp_pdf_dir):
        """Test that malware scanner blocks dangerous PDFs."""
        scanner = PDFScanner(mock_db, scan_content=False, enable_malware_scan=True)
        
        # Create PDF with JavaScript (high risk)
        dangerous_content = b'%PDF-1.4\n/JavaScript (alert("test"))\n%%EOF'
        pdf_path = temp_pdf_dir / "dangerous.pdf"
        pdf_path.write_bytes(dangerous_content)
        
        result = scanner.scan_folder(str(temp_pdf_dir))
        
        # Should have error due to malware detection
        assert result.errors >= 1 or result.unmatched >= 1


# =============================================================================
# DATA CLASS TESTS
# =============================================================================

class TestScannedPDF:
    """Tests for ScannedPDF dataclass."""

    def test_scanned_pdf_creation(self, temp_pdf_dir):
        """Test ScannedPDF creation."""
        pdf = ScannedPDF(
            filepath=temp_pdf_dir / "test.pdf",
            filename="test.pdf",
            vendor_name="Test Vendor",
            invoice_number="INV-001",
            matched=True,
            extraction_method="filename",
            confidence=1.0
        )
        
        assert pdf.filename == "test.pdf"
        assert pdf.vendor_name == "Test Vendor"
        assert pdf.invoice_number == "INV-001"
        assert pdf.matched is True

    def test_scanned_pdf_str_matched(self, temp_pdf_dir):
        """Test ScannedPDF string representation when matched."""
        pdf = ScannedPDF(
            filepath=temp_pdf_dir / "test.pdf",
            filename="test.pdf",
            vendor_name="Test Vendor",
            invoice_number="INV-001",
            matched=True
        )
        
        str_repr = str(pdf)
        
        assert "test.pdf" in str_repr
        assert "INV-001" in str_repr

    def test_scanned_pdf_str_unmatched(self, temp_pdf_dir):
        """Test ScannedPDF string representation when unmatched."""
        pdf = ScannedPDF(
            filepath=temp_pdf_dir / "test.pdf",
            filename="test.pdf",
            vendor_name=None,
            invoice_number=None,
            matched=False
        )
        
        str_repr = str(pdf)
        
        assert "NO MATCH" in str_repr


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_scan_result_creation(self):
        """Test ScanResult creation."""
        result = ScanResult(
            total_files=10,
            matched=7,
            unmatched=2,
            errors=1,
            matched_invoices=["INV-001", "INV-002"],
            unmatched_files=["unknown.pdf"],
            content_matches=3,
            ocr_matches=1
        )
        
        assert result.total_files == 10
        assert result.matched == 7
        assert result.unmatched == 2
        assert result.errors == 1

    def test_scan_result_str(self):
        """Test ScanResult string representation."""
        result = ScanResult(
            total_files=10,
            matched=7,
            unmatched=2,
            errors=1,
            matched_invoices=["INV-001"],
            unmatched_files=["unknown.pdf"],
            content_matches=3,
            ocr_matches=1
        )
        
        str_repr = str(result)
        
        assert "10" in str_repr
        assert "7" in str_repr
        assert "content" in str_repr.lower()


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_malware_scanner_custom_max_size(self):
        """Test custom max file size configuration."""
        scanner = PDFMalwareScanner(max_file_size=1024)
        
        assert scanner.max_file_size == 1024

    def test_content_extractor_without_ocr(self):
        """Test content extractor with OCR disabled."""
        extractor = PDFContentExtractor(use_ocr=False)
        
        assert extractor.use_ocr is False

    def test_invoice_number_validation(self, content_extractor):
        """Test that short strings are not matched as invoice numbers."""
        text = "ID: 123"  # Too short
        
        results = content_extractor.find_invoice_numbers(text)
        
        # Should not match very short numbers
        for inv_num, conf in results:
            assert len(inv_num) >= 4

    def test_vendor_name_length_limit(self, content_extractor):
        """Test vendor name length is limited."""
        long_vendor = "A" * 200
        text = f"Kiállító: {long_vendor}\nAdószám: 12345678"
        
        vendor = content_extractor.find_vendor_name(text)
        
        if vendor:
            assert len(vendor) <= 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
