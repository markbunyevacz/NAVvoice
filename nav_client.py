"""
NAV Online Számla v3.0 API Client

Implements connection to Hungarian Tax Authority (NAV) invoice query API
with proper XML signature handling per NAV specifications.

API Documentation: https://onlineszamla.nav.gov.hu/api/files/container/download/Online%20Szamla_INTERFESZ_specifikacio_3.0_HU.pdf
"""

import hashlib
import uuid
import time
import base64
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import requests
from lxml import etree

logger = logging.getLogger(__name__)

# NAV API Configuration
NAV_API_BASE_URL = "https://api.onlineszamla.nav.gov.hu/invoiceService/v3"
NAV_API_TEST_URL = "https://api-test.onlineszamla.nav.gov.hu/invoiceService/v3"

# XML Namespaces
NAMESPACES = {
    'common': 'http://schemas.nav.gov.hu/OSA/3.0/common',
    'api': 'http://schemas.nav.gov.hu/OSA/3.0/api',
    'data': 'http://schemas.nav.gov.hu/OSA/3.0/data',
}


class NavErrorCode(Enum):
    """Standard NAV API error codes that warrant retry"""
    OPERATION_FAILED = "OPERATION_FAILED"
    MAINTENANCE = "MAINTENANCE"
    TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS"
    TECHNICAL_ERROR = "TECHNICAL_ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass
class NavCredentials:
    """NAV Technical User credentials container"""
    login: str                    # Technical user login name
    password: str                 # Technical user password (will be hashed)
    signature_key: str            # XML signing key (32 chars)
    replacement_key: str          # Key replacement (32 chars)
    tax_number: str              # Company tax number (8 digits)
    
    def __post_init__(self):
        if len(self.signature_key) != 32:
            raise ValueError("Signature key must be exactly 32 characters")
        if len(self.replacement_key) != 32:
            raise ValueError("Replacement key must be exactly 32 characters")
        if not self.tax_number.isdigit() or len(self.tax_number) != 8:
            raise ValueError("Tax number must be 8 digits")


@dataclass
class InvoiceData:
    """Parsed invoice data from NAV response"""
    invoice_number: str
    supplier_name: str
    supplier_tax_number: str
    invoice_date: str
    gross_amount: float
    currency: str = "HUF"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "invoiceNumber": self.invoice_number,
            "supplierName": self.supplier_name,
            "supplierTaxNumber": self.supplier_tax_number,
            "invoiceDate": self.invoice_date,
            "grossAmount": self.gross_amount,
            "currency": self.currency,
        }


class NavApiError(Exception):
    """Custom exception for NAV API errors"""
    def __init__(self, code: str, message: str, technical_message: str = ""):
        self.code = code
        self.message = message
        self.technical_message = technical_message
        super().__init__(f"NAV API Error [{code}]: {message}")
    
    @property
    def is_retryable(self) -> bool:
        """Check if this error warrants a retry attempt"""
        retryable_codes = [e.value for e in NavErrorCode]
        return self.code in retryable_codes


class NavClient:
    """
    NAV Online Számla v3.0 API Client
    
    Handles authentication, XML signature generation, and invoice queries
    according to NAV API specifications.
    
    Usage:
        credentials = NavCredentials(
            login="technicalUser",
            password="password123",
            signature_key="32-char-signature-key-here......",
            replacement_key="32-char-replacement-key-here...",
            tax_number="12345678"
        )
        client = NavClient(credentials, use_test_api=True)
        invoices = client.query_incoming_invoices(
            issue_date_from="2024-01-01",
            issue_date_to="2024-01-31"
        )
    """
    
    SOFTWARE_ID = "HU12345678-1234"  # Replace with registered software ID
    SOFTWARE_NAME = "NAV Invoice Reconciliation"
    SOFTWARE_VERSION = "1.0.0"
    SOFTWARE_DEV_NAME = "Your Company Name"
    SOFTWARE_DEV_CONTACT = "dev@company.hu"
    
    MAX_RETRIES = 3
    RETRY_DELAY_BASE = 2  # Exponential backoff base in seconds
    REQUEST_TIMEOUT = 30  # seconds
    
    def __init__(
        self,
        credentials: NavCredentials,
        use_test_api: bool = False,
        software_id: Optional[str] = None
    ):
        """
        Initialize NAV API client.
        
        Args:
            credentials: NAV technical user credentials
            use_test_api: Use NAV test environment (default: False)
            software_id: Override default software ID
        """
        self.credentials = credentials
        self.base_url = NAV_API_TEST_URL if use_test_api else NAV_API_BASE_URL
        self.software_id = software_id or self.SOFTWARE_ID
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/xml",
            "Accept": "application/xml",
        })

    # =========================================================================
    # CRYPTOGRAPHIC METHODS (SHA-512 per NAV specification)
    # =========================================================================

    @staticmethod
    def _generate_request_id() -> str:
        """
        Generate unique request ID per NAV specification.
        Format: RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR (30 chars, alphanumeric + _)
        """
        # UUID without hyphens, uppercase, truncated to 30 chars
        return str(uuid.uuid4()).replace("-", "").upper()[:30]

    @staticmethod
    def _get_utc_timestamp() -> str:
        """
        Get current UTC timestamp in NAV required format.
        Format: 2024-01-15T10:30:00.000Z
        """
        now = datetime.now(timezone.utc)
        return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

    @staticmethod
    def _hash_sha512(data: str) -> str:
        """
        Compute SHA-512 hash and return uppercase hex string.

        Args:
            data: String to hash

        Returns:
            Uppercase hexadecimal hash string (128 chars)
        """
        return hashlib.sha512(data.encode('utf-8')).hexdigest().upper()

    def _compute_password_hash(self) -> str:
        """
        Hash the password per NAV specification.
        Formula: SHA-512(password)

        Returns:
            Uppercase hex SHA-512 hash of password
        """
        return self._hash_sha512(self.credentials.password)

    def _compute_request_signature(self, request_id: str, timestamp: str) -> str:
        """
        Compute request signature per NAV v3.0 specification.

        Formula: SHA-512(requestId + timestamp + signatureKey)

        The signature proves the request authenticity by combining:
        - requestId: Unique request identifier
        - timestamp: Request creation time (UTC)
        - signatureKey: Technical user's signing key

        Args:
            request_id: Unique request ID (30 chars)
            timestamp: UTC timestamp in ISO format

        Returns:
            Uppercase hex SHA-512 hash (128 chars)
        """
        # Remove timestamp separators per NAV spec: 2024-01-15T10:30:00.000Z -> 20240115103000
        timestamp_clean = timestamp.replace("-", "").replace("T", "").replace(":", "").replace(".", "").replace("Z", "")[:14]

        signature_data = request_id + timestamp_clean + self.credentials.signature_key
        return self._hash_sha512(signature_data)

    # =========================================================================
    # XML REQUEST BUILDING
    # =========================================================================

    def _build_basic_header(self, request_id: str, timestamp: str) -> etree.Element:
        """Build the common header element for all requests."""
        header = etree.Element("{%s}header" % NAMESPACES['common'])

        etree.SubElement(header, "{%s}requestId" % NAMESPACES['common']).text = request_id
        etree.SubElement(header, "{%s}timestamp" % NAMESPACES['common']).text = timestamp
        etree.SubElement(header, "{%s}requestVersion" % NAMESPACES['common']).text = "3.0"
        etree.SubElement(header, "{%s}headerVersion" % NAMESPACES['common']).text = "1.0"

        return header

    def _build_user_element(self, request_id: str, timestamp: str) -> etree.Element:
        """Build the user authentication element."""
        user = etree.Element("{%s}user" % NAMESPACES['common'])

        etree.SubElement(user, "{%s}login" % NAMESPACES['common']).text = self.credentials.login
        etree.SubElement(user, "{%s}passwordHash" % NAMESPACES['common']).text = self._compute_password_hash()
        etree.SubElement(user, "{%s}taxNumber" % NAMESPACES['common']).text = self.credentials.tax_number
        etree.SubElement(user, "{%s}requestSignature" % NAMESPACES['common']).text = self._compute_request_signature(request_id, timestamp)

        return user

    def _build_software_element(self) -> etree.Element:
        """Build the software identification element."""
        software = etree.Element("{%s}software" % NAMESPACES['api'])

        etree.SubElement(software, "{%s}softwareId" % NAMESPACES['api']).text = self.software_id
        etree.SubElement(software, "{%s}softwareName" % NAMESPACES['api']).text = self.SOFTWARE_NAME
        etree.SubElement(software, "{%s}softwareOperation" % NAMESPACES['api']).text = "ONLINE_SERVICE"
        etree.SubElement(software, "{%s}softwareMainVersion" % NAMESPACES['api']).text = self.SOFTWARE_VERSION
        etree.SubElement(software, "{%s}softwareDevName" % NAMESPACES['api']).text = self.SOFTWARE_DEV_NAME
        etree.SubElement(software, "{%s}softwareDevContact" % NAMESPACES['api']).text = self.SOFTWARE_DEV_CONTACT

        return software

    # =========================================================================
    # QUERY INVOICE DATA ENDPOINT
    # =========================================================================

    def _build_query_invoice_data_request(
        self,
        invoice_direction: str,
        issue_date_from: str,
        issue_date_to: str,
        page: int = 1
    ) -> bytes:
        """
        Build XML request for /queryInvoiceData endpoint.

        Args:
            invoice_direction: "INBOUND" for incoming, "OUTBOUND" for outgoing
            issue_date_from: Start date (YYYY-MM-DD)
            issue_date_to: End date (YYYY-MM-DD)
            page: Page number (1-based)

        Returns:
            UTF-8 encoded XML request body
        """
        request_id = self._generate_request_id()
        timestamp = self._get_utc_timestamp()

        # Build root element with namespaces
        nsmap = {
            None: NAMESPACES['api'],
            'common': NAMESPACES['common'],
        }
        root = etree.Element("QueryInvoiceDataRequest", nsmap=nsmap)

        # Add header, user, software elements
        root.append(self._build_basic_header(request_id, timestamp))
        root.append(self._build_user_element(request_id, timestamp))
        root.append(self._build_software_element())

        # Add invoice query params
        invoice_query = etree.SubElement(root, "invoiceNumberQuery")
        etree.SubElement(invoice_query, "invoiceDirection").text = invoice_direction

        # Mandatory date range
        mandatory_params = etree.SubElement(invoice_query, "mandatoryQueryParams")
        issue_date = etree.SubElement(mandatory_params, "invoiceIssueDate")
        etree.SubElement(issue_date, "dateFrom").text = issue_date_from
        etree.SubElement(issue_date, "dateTo").text = issue_date_to

        # Pagination
        etree.SubElement(root, "page").text = str(page)

        # Serialize with XML declaration
        return etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True
        )

    def _parse_invoice_response(self, response_xml: bytes) -> List[InvoiceData]:
        """
        Parse XML response from queryInvoiceData endpoint.

        Args:
            response_xml: Raw XML response bytes

        Returns:
            List of parsed InvoiceData objects
        """
        root = etree.fromstring(response_xml)
        invoices = []

        # Find all invoice digest elements
        for invoice_elem in root.findall(".//{%s}invoiceDigest" % NAMESPACES['api']):
            try:
                invoice_number = self._get_text(invoice_elem, "invoiceNumber", "")
                supplier_name = self._get_text(invoice_elem, "supplierName", "Unknown")
                supplier_tax = self._get_text(invoice_elem, "supplierTaxNumber", "")
                invoice_date = self._get_text(invoice_elem, "invoiceIssueDate", "")
                gross_amount_str = self._get_text(invoice_elem, "invoiceGrossAmount", "0")
                currency = self._get_text(invoice_elem, "currencyCode", "HUF")

                invoices.append(InvoiceData(
                    invoice_number=invoice_number,
                    supplier_name=supplier_name,
                    supplier_tax_number=supplier_tax,
                    invoice_date=invoice_date,
                    gross_amount=float(gross_amount_str),
                    currency=currency
                ))
            except (ValueError, AttributeError) as e:
                # Log malformed invoice and continue
                print(f"Warning: Could not parse invoice element: {e}")
                continue

        return invoices

    @staticmethod
    def _get_text(element: etree.Element, tag: str, default: str = "") -> str:
        """Safely extract text from child element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        # Try with namespace
        for ns in NAMESPACES.values():
            child = element.find("{%s}%s" % (ns, tag))
            if child is not None and child.text:
                return child.text.strip()
        return default

    def _check_response_for_errors(self, response_xml: bytes) -> None:
        """
        Check NAV response for error codes and raise appropriate exceptions.

        Args:
            response_xml: Raw XML response bytes

        Raises:
            NavApiError: If response contains error
        """
        root = etree.fromstring(response_xml)

        # Check for funcCode != OK
        func_code = root.find(".//{%s}funcCode" % NAMESPACES['common'])
        if func_code is not None and func_code.text != "OK":
            error_code = self._get_text(root, "errorCode", "UNKNOWN")
            error_msg = self._get_text(root, "message", "Unknown error")
            tech_msg = self._get_text(root, "technicalDetails", "")
            raise NavApiError(error_code, error_msg, tech_msg)

    # =========================================================================
    # RETRY MECHANISM
    # =========================================================================

    def _execute_with_retry(
        self,
        endpoint: str,
        request_body: bytes,
        max_retries: Optional[int] = None
    ) -> bytes:
        """
        Execute API request with exponential backoff retry for transient errors.

        Args:
            endpoint: API endpoint path (e.g., "/queryInvoiceData")
            request_body: UTF-8 encoded XML request
            max_retries: Override default max retries

        Returns:
            Raw response bytes

        Raises:
            NavApiError: If all retries exhausted or non-retryable error
            requests.RequestException: For network-level failures
        """
        retries = max_retries or self.MAX_RETRIES
        last_error = None

        for attempt in range(retries + 1):
            try:
                url = f"{self.base_url}{endpoint}"

                response = self.session.post(
                    url,
                    data=request_body,
                    timeout=self.REQUEST_TIMEOUT
                )

                # Check HTTP status
                if response.status_code != 200:
                    raise NavApiError(
                        code=f"HTTP_{response.status_code}",
                        message=f"HTTP error {response.status_code}",
                        technical_message=response.text[:500]
                    )

                # Check for NAV-level errors in response
                self._check_response_for_errors(response.content)

                return response.content

            except NavApiError as e:
                last_error = e
                if not e.is_retryable or attempt >= retries:
                    raise

                # Exponential backoff: 2^attempt seconds
                delay = self.RETRY_DELAY_BASE ** attempt
                print(f"NAV API error (attempt {attempt + 1}/{retries + 1}): {e.code}. "
                      f"Retrying in {delay}s...")
                time.sleep(delay)

            except requests.Timeout:
                last_error = NavApiError("TIMEOUT", "Request timed out")
                if attempt >= retries:
                    raise last_error
                delay = self.RETRY_DELAY_BASE ** attempt
                print(f"Timeout (attempt {attempt + 1}/{retries + 1}). Retrying in {delay}s...")
                time.sleep(delay)

            except requests.RequestException as e:
                # Network errors - retry
                last_error = NavApiError("NETWORK_ERROR", str(e))
                if attempt >= retries:
                    raise last_error
                delay = self.RETRY_DELAY_BASE ** attempt
                print(f"Network error (attempt {attempt + 1}/{retries + 1}): {e}. "
                      f"Retrying in {delay}s...")
                time.sleep(delay)

        raise last_error or NavApiError("UNKNOWN", "Unknown error after retries")

    # =========================================================================
    # PUBLIC API METHODS
    # =========================================================================

    def query_incoming_invoices(
        self,
        issue_date_from: str,
        issue_date_to: str,
        page: int = 1,
        fetch_all_pages: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Query incoming (inbound) invoices from NAV for the specified date range.

        This is the main method to fetch invoices received by your company
        from suppliers, as recorded in NAV's Online Számla system.

        Args:
            issue_date_from: Start date in YYYY-MM-DD format
            issue_date_to: End date in YYYY-MM-DD format
            page: Starting page number (1-based)
            fetch_all_pages: If True, automatically fetch all pages

        Returns:
            List of invoice dictionaries with keys:
            - invoiceNumber: str
            - supplierName: str
            - supplierTaxNumber: str
            - invoiceDate: str (YYYY-MM-DD)
            - grossAmount: float
            - currency: str

        Raises:
            NavApiError: On API errors (after retry exhaustion)
            ValueError: On invalid input parameters

        Example:
            >>> client = NavClient(credentials)
            >>> invoices = client.query_incoming_invoices(
            ...     issue_date_from="2024-01-01",
            ...     issue_date_to="2024-01-31"
            ... )
            >>> print(f"Found {len(invoices)} invoices")
        """
        # Validate date format
        self._validate_date_format(issue_date_from)
        self._validate_date_format(issue_date_to)

        all_invoices: List[InvoiceData] = []
        current_page = page

        while True:
            request_body = self._build_query_invoice_data_request(
                invoice_direction="INBOUND",
                issue_date_from=issue_date_from,
                issue_date_to=issue_date_to,
                page=current_page
            )

            response = self._execute_with_retry("/queryInvoiceData", request_body)
            page_invoices = self._parse_invoice_response(response)

            all_invoices.extend(page_invoices)

            # Check if more pages available
            if not fetch_all_pages or len(page_invoices) == 0:
                break

            # NAV returns max 100 invoices per page
            if len(page_invoices) < 100:
                break

            current_page += 1

            # Rate limiting: NAV allows max 1 request/second
            time.sleep(1.1)

        return [inv.to_dict() for inv in all_invoices]

    def query_outgoing_invoices(
        self,
        issue_date_from: str,
        issue_date_to: str,
        page: int = 1,
        fetch_all_pages: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Query outgoing (outbound) invoices from NAV.

        Same as query_incoming_invoices but for invoices your company issued.
        """
        self._validate_date_format(issue_date_from)
        self._validate_date_format(issue_date_to)

        all_invoices: List[InvoiceData] = []
        current_page = page

        while True:
            request_body = self._build_query_invoice_data_request(
                invoice_direction="OUTBOUND",
                issue_date_from=issue_date_from,
                issue_date_to=issue_date_to,
                page=current_page
            )

            response = self._execute_with_retry("/queryInvoiceData", request_body)
            page_invoices = self._parse_invoice_response(response)
            all_invoices.extend(page_invoices)

            if not fetch_all_pages or len(page_invoices) < 100:
                break

            current_page += 1
            time.sleep(1.1)

        return [inv.to_dict() for inv in all_invoices]

    @staticmethod
    def _validate_date_format(date_str: str) -> None:
        """Validate date string is in YYYY-MM-DD format."""
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"Invalid date format: {date_str}. Expected YYYY-MM-DD")

    def test_connection(self) -> bool:
        """
        Test API connection and credentials validity.

        Returns:
            True if connection successful

        Raises:
            NavApiError: If authentication fails
        """
        try:
            # Query a single day to minimize load
            today = datetime.now().strftime("%Y-%m-%d")
            self.query_incoming_invoices(
                issue_date_from=today,
                issue_date_to=today,
                fetch_all_pages=False
            )
            return True
        except NavApiError:
            raise

    # =========================================================================
    # QUERY INVOICE DIGEST ENDPOINT (Summary Data)
    # =========================================================================

    def _build_query_invoice_digest_request(
        self,
        invoice_direction: str,
        issue_date_from: str,
        issue_date_to: str,
        page: int = 1,
        supplier_tax_number: Optional[str] = None,
        invoice_category: Optional[str] = None
    ) -> bytes:
        """
        Build XML request for /queryInvoiceDigest endpoint.

        This endpoint returns summary information about invoices,
        which is faster than queryInvoiceData but with less detail.

        Args:
            invoice_direction: "INBOUND" for incoming, "OUTBOUND" for outgoing
            issue_date_from: Start date (YYYY-MM-DD)
            issue_date_to: End date (YYYY-MM-DD)
            page: Page number (1-based)
            supplier_tax_number: Optional filter by supplier tax number
            invoice_category: Optional filter: "NORMAL", "SIMPLIFIED", "AGGREGATE"

        Returns:
            UTF-8 encoded XML request body
        """
        request_id = self._generate_request_id()
        timestamp = self._get_utc_timestamp()

        # Build root element with namespaces
        nsmap = {
            None: NAMESPACES['api'],
            'common': NAMESPACES['common'],
        }
        root = etree.Element("QueryInvoiceDigestRequest", nsmap=nsmap)

        # Add header, user, software elements
        root.append(self._build_basic_header(request_id, timestamp))
        root.append(self._build_user_element(request_id, timestamp))
        root.append(self._build_software_element())

        # Add page number
        etree.SubElement(root, "page").text = str(page)

        # Add invoice direction
        etree.SubElement(root, "invoiceDirection").text = invoice_direction

        # Add mandatory query params (date range)
        mandatory_params = etree.SubElement(root, "mandatoryQueryParams")
        issue_date = etree.SubElement(mandatory_params, "invoiceIssueDate")
        etree.SubElement(issue_date, "dateFrom").text = issue_date_from
        etree.SubElement(issue_date, "dateTo").text = issue_date_to

        # Add optional filters
        if supplier_tax_number or invoice_category:
            additional_params = etree.SubElement(root, "additionalQueryParams")

            if supplier_tax_number:
                etree.SubElement(additional_params, "supplierTaxNumber").text = supplier_tax_number

            if invoice_category:
                etree.SubElement(additional_params, "invoiceCategory").text = invoice_category

        return etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True
        )

    def _parse_invoice_digest_response(self, response_xml: bytes) -> List[Dict[str, Any]]:
        """
        Parse XML response from queryInvoiceDigest endpoint.

        Returns digest (summary) format with additional metadata.
        """
        root = etree.fromstring(response_xml)
        digests = []

        # Find all invoice digest elements
        for digest_elem in root.findall(".//{%s}invoiceDigest" % NAMESPACES['api']):
            try:
                digest = {
                    "invoiceNumber": self._get_text(digest_elem, "invoiceNumber", ""),
                    "batchIndex": int(self._get_text(digest_elem, "batchIndex", "1")),
                    "invoiceOperation": self._get_text(digest_elem, "invoiceOperation", "CREATE"),
                    "invoiceCategory": self._get_text(digest_elem, "invoiceCategory", "NORMAL"),
                    "invoiceIssueDate": self._get_text(digest_elem, "invoiceIssueDate", ""),
                    "supplierTaxNumber": self._get_text(digest_elem, "supplierTaxNumber", ""),
                    "supplierGroupMemberTaxNumber": self._get_text(digest_elem, "supplierGroupMemberTaxNumber", ""),
                    "supplierName": self._get_text(digest_elem, "supplierName", "Unknown"),
                    "customerTaxNumber": self._get_text(digest_elem, "customerTaxNumber", ""),
                    "customerGroupMemberTaxNumber": self._get_text(digest_elem, "customerGroupMemberTaxNumber", ""),
                    "customerName": self._get_text(digest_elem, "customerName", ""),
                    "paymentMethod": self._get_text(digest_elem, "paymentMethod", ""),
                    "paymentDate": self._get_text(digest_elem, "paymentDate", ""),
                    "invoiceAppearance": self._get_text(digest_elem, "invoiceAppearance", ""),
                    "source": self._get_text(digest_elem, "source", ""),
                    "invoiceDeliveryDate": self._get_text(digest_elem, "invoiceDeliveryDate", ""),
                    "currency": self._get_text(digest_elem, "currency", "HUF"),
                    "invoiceNetAmount": float(self._get_text(digest_elem, "invoiceNetAmount", "0")),
                    "invoiceNetAmountHUF": float(self._get_text(digest_elem, "invoiceNetAmountHUF", "0")),
                    "invoiceVatAmount": float(self._get_text(digest_elem, "invoiceVatAmount", "0")),
                    "invoiceVatAmountHUF": float(self._get_text(digest_elem, "invoiceVatAmountHUF", "0")),
                    "transactionId": self._get_text(digest_elem, "transactionId", ""),
                    "index": int(self._get_text(digest_elem, "index", "1")),
                    "originalInvoiceNumber": self._get_text(digest_elem, "originalInvoiceNumber", ""),
                    "modificationIndex": int(self._get_text(digest_elem, "modificationIndex", "0")),
                    "insDate": self._get_text(digest_elem, "insDate", ""),
                    "completenessIndicator": self._get_text(digest_elem, "completenessIndicator", "false") == "true",
                }
                digests.append(digest)

            except (ValueError, AttributeError) as e:
                logger.warning(f"Could not parse invoice digest element: {e}")
                continue

        return digests

    def query_invoice_digest(
        self,
        invoice_direction: str,
        issue_date_from: str,
        issue_date_to: str,
        page: int = 1,
        fetch_all_pages: bool = True,
        supplier_tax_number: Optional[str] = None,
        invoice_category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Query invoice digest (summary) from NAV.

        This is faster than queryInvoiceData as it returns less detail,
        but includes important metadata like transactionId for further queries.

        Args:
            invoice_direction: "INBOUND" for incoming, "OUTBOUND" for outgoing
            issue_date_from: Start date (YYYY-MM-DD)
            issue_date_to: End date (YYYY-MM-DD)
            page: Starting page (1-based)
            fetch_all_pages: Auto-fetch all pages
            supplier_tax_number: Filter by supplier
            invoice_category: Filter: "NORMAL", "SIMPLIFIED", "AGGREGATE"

        Returns:
            List of invoice digest dictionaries with keys:
            - invoiceNumber, supplierName, supplierTaxNumber
            - invoiceIssueDate, invoiceDeliveryDate
            - invoiceNetAmount, invoiceVatAmount, currency
            - transactionId (for detailed queries)
            - invoiceOperation (CREATE, MODIFY, STORNO)
            - completenessIndicator, etc.

        Example:
            >>> digests = client.query_invoice_digest(
            ...     invoice_direction="INBOUND",
            ...     issue_date_from="2024-01-01",
            ...     issue_date_to="2024-01-31",
            ...     supplier_tax_number="12345678"
            ... )
        """
        self._validate_date_format(issue_date_from)
        self._validate_date_format(issue_date_to)

        if invoice_category and invoice_category not in ["NORMAL", "SIMPLIFIED", "AGGREGATE"]:
            raise ValueError(f"Invalid invoice_category: {invoice_category}")

        all_digests: List[Dict[str, Any]] = []
        current_page = page

        while True:
            request_body = self._build_query_invoice_digest_request(
                invoice_direction=invoice_direction,
                issue_date_from=issue_date_from,
                issue_date_to=issue_date_to,
                page=current_page,
                supplier_tax_number=supplier_tax_number,
                invoice_category=invoice_category
            )

            response = self._execute_with_retry("/queryInvoiceDigest", request_body)
            page_digests = self._parse_invoice_digest_response(response)

            all_digests.extend(page_digests)

            if not fetch_all_pages or len(page_digests) == 0:
                break

            # NAV returns max 100 items per page
            if len(page_digests) < 100:
                break

            current_page += 1
            time.sleep(1.1)  # Rate limit: 1 req/sec

        return all_digests

    def query_incoming_invoice_digest(
        self,
        issue_date_from: str,
        issue_date_to: str,
        supplier_tax_number: Optional[str] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Convenience method for querying incoming invoice digests.

        Args:
            issue_date_from: Start date (YYYY-MM-DD)
            issue_date_to: End date (YYYY-MM-DD)
            supplier_tax_number: Optional filter by supplier
            **kwargs: Additional arguments passed to query_invoice_digest

        Returns:
            List of incoming invoice digest dictionaries
        """
        return self.query_invoice_digest(
            invoice_direction="INBOUND",
            issue_date_from=issue_date_from,
            issue_date_to=issue_date_to,
            supplier_tax_number=supplier_tax_number,
            **kwargs
        )

    def query_outgoing_invoice_digest(
        self,
        issue_date_from: str,
        issue_date_to: str,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Convenience method for querying outgoing invoice digests.
        """
        return self.query_invoice_digest(
            invoice_direction="OUTBOUND",
            issue_date_from=issue_date_from,
            issue_date_to=issue_date_to,
            **kwargs
        )


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == "__main__":
    """
    Example usage of NavClient.

    Before running:
    1. Register your software at NAV Online Számla portal
    2. Create a Technical User and obtain credentials
    3. Set environment variables or replace placeholders below
    """
    import os

    # Load credentials from environment (recommended) or replace with actual values
    credentials = NavCredentials(
        login=os.getenv("NAV_TECHNICAL_USER", "your_technical_user"),
        password=os.getenv("NAV_PASSWORD", "your_password"),
        signature_key=os.getenv("NAV_SIGNATURE_KEY", "12345678901234567890123456789012"),
        replacement_key=os.getenv("NAV_REPLACEMENT_KEY", "12345678901234567890123456789012"),
        tax_number=os.getenv("NAV_TAX_NUMBER", "12345678")
    )

    # Initialize client (use test API for development)
    client = NavClient(
        credentials=credentials,
        use_test_api=True,  # Set to False for production
        software_id="HU12345678-0001"  # Your registered software ID
    )

    try:
        # Test connection
        print("Testing NAV API connection...")
        client.test_connection()
        print("✓ Connection successful!")

        # Query last month's incoming invoices
        from datetime import datetime, timedelta

        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)

        print(f"\nQuerying invoices from {start_date.date()} to {end_date.date()}...")
        invoices = client.query_incoming_invoices(
            issue_date_from=start_date.strftime("%Y-%m-%d"),
            issue_date_to=end_date.strftime("%Y-%m-%d")
        )

        print(f"\n✓ Found {len(invoices)} incoming invoices:")
        for inv in invoices[:5]:  # Show first 5
            print(f"  - {inv['invoiceNumber']}: {inv['supplierName']} "
                  f"({inv['grossAmount']:,.0f} {inv.get('currency', 'HUF')})")

        if len(invoices) > 5:
            print(f"  ... and {len(invoices) - 5} more")

    except NavApiError as e:
        print(f"✗ NAV API Error: {e}")
        if e.technical_message:
            print(f"  Technical details: {e.technical_message}")
    except Exception as e:
        print(f"✗ Error: {e}")
