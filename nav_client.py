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
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

logger = logging.getLogger(__name__)

# NAV API Configuration
NAV_API_BASE_URL = "https://api.onlineszamla.nav.gov.hu/invoiceService/v3"
NAV_API_TEST_URL = "https://api-test.onlineszamla.nav.gov.hu/invoiceService/v3"

# XML Namespaces
NAMESPACES = {
    'common': 'http://schemas.nav.gov.hu/NTCA/1.0/common',
    'api': 'http://schemas.nav.gov.hu/OSA/3.0/api',
    'data': 'http://schemas.nav.gov.hu/OSA/3.0/data',
    'base': 'http://schemas.nav.gov.hu/OSA/3.0/base',
}


class NavErrorCode(Enum):
    """
    NAV API error codes.

    Retryable errors: Transient failures that may succeed on retry
    Non-retryable errors: Permanent failures requiring code/data fixes
    Validation errors: Sept 2025 blocking validation errors
    """
    # Retryable errors (transient failures)
    OPERATION_FAILED = "OPERATION_FAILED"
    MAINTENANCE = "MAINTENANCE"
    TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS"
    TECHNICAL_ERROR = "TECHNICAL_ERROR"
    TIMEOUT = "TIMEOUT"

    # Non-retryable errors (permanent failures)
    INVALID_REQUEST_SIGNATURE = "INVALID_REQUEST_SIGNATURE"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    INVALID_EXCHANGE_KEY = "INVALID_EXCHANGE_KEY"
    EMPTY_TOKEN = "EMPTY_TOKEN"
    TOKEN_DECRYPTION_FAILED = "TOKEN_DECRYPTION_FAILED"

    # September 2025 validation errors (will become blocking)
    VAT_RATE_MISMATCH = "435"  # VAT rate doesn't match tax number
    VAT_SUMMARY_MISMATCH = "734"  # VAT summary calculation error
    VAT_LINE_ITEM_ERROR = "1311"  # VAT line item inconsistency


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


class NavApiError(Exception):
    """Custom exception for NAV API errors"""
    def __init__(self, code: str, message: str, technical_message: str = ""):
        self.code = code
        self.message = message
        self.technical_message = technical_message
        super().__init__(f"NAV API Error [{code}]: {message}")

    @property
    def is_retryable(self) -> bool:
        """
        Check if this error warrants a retry attempt.

        Only transient errors (OPERATION_FAILED, MAINTENANCE, etc.) are retryable.
        Authentication errors, validation errors, and decryption errors are not.
        """
        retryable_codes = [
            NavErrorCode.OPERATION_FAILED.value,
            NavErrorCode.MAINTENANCE.value,
            NavErrorCode.TOO_MANY_REQUESTS.value,
            NavErrorCode.TECHNICAL_ERROR.value,
            NavErrorCode.TIMEOUT.value,
        ]
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

        # Rate limiting: NAV API enforces 1 request per second per IP
        self._last_request_time = 0.0
        self._rate_limit_delay = 1.0  # seconds


    def _enforce_rate_limit(self):
        """
        Enforce NAV API rate limit of 1 request per second per IP address.

        This method ensures compliance with NAV API rate limiting by introducing
        a delay if the time since the last request is less than 1 second.

        Per NAV specification: Exceeding the rate limit triggers cumulative
        4-second delays on subsequent requests.
        """
        elapsed = time.time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            sleep_time = self._rate_limit_delay - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.3f}s")
            time.sleep(sleep_time)
        self._last_request_time = time.time()

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
        Used for password hashing.
        """
        return hashlib.sha512(data.encode('utf-8')).hexdigest().upper()

    @staticmethod
    def _hash_sha3_512(data: str) -> str:
        """
        Compute SHA3-512 hash and return uppercase hex string.
        Used for request signatures per API v3.0 spec.
        """
        return hashlib.sha3_512(data.encode('utf-8')).hexdigest().upper()

    def _compute_password_hash(self) -> str:
        """
        Hash the password per NAV specification.
        Formula: SHA-512(password)
        """
        return self._hash_sha512(self.credentials.password)

    def _compute_request_signature(self, request_id: str, timestamp: str, additional_data: str = "") -> str:
        """
        Compute request signature per NAV v3.0 specification.

        Formula: SHA3-512(requestId + timestamp + signatureKey + additional_data)

        Args:
            request_id: Unique request ID (30 chars)
            timestamp: UTC timestamp in ISO format
            additional_data: Concatenated invoice hashes for manageInvoice, empty for others
        """
        # Remove timestamp separators per NAV spec: 2024-01-15T10:30:00.000Z -> 20240115103000
        # Format is YYYYMMDDHHmmss
        timestamp_clean = timestamp.replace("-", "").replace("T", "").replace(":", "").replace(".", "").replace("Z", "")[:14]

        signature_data = request_id + timestamp_clean + self.credentials.signature_key + additional_data
        return self._hash_sha3_512(signature_data)

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

    def _build_user_element(self, request_id: str, timestamp: str, additional_signature_data: str = "") -> etree.Element:
        """Build the user authentication element."""
        user = etree.Element("{%s}user" % NAMESPACES['common'])

        etree.SubElement(user, "{%s}login" % NAMESPACES['common']).text = self.credentials.login
        etree.SubElement(user, "{%s}passwordHash" % NAMESPACES['common']).text = self._compute_password_hash()

        # Set cryptoType explicitly
        password_hash_elem = user.find("{%s}passwordHash" % NAMESPACES['common'])
        password_hash_elem.set("cryptoType", "SHA-512")

        etree.SubElement(user, "{%s}taxNumber" % NAMESPACES['common']).text = self.credentials.tax_number

        signature = self._compute_request_signature(request_id, timestamp, additional_signature_data)
        req_sig = etree.SubElement(user, "{%s}requestSignature" % NAMESPACES['common'])
        req_sig.text = signature
        req_sig.set("cryptoType", "SHA3-512")

        return user

    def _build_token_exchange_request(self) -> bytes:
        """
        Build XML request for /tokenExchange endpoint.
        Used to obtain a session token for write operations.
        """
        request_id = self._generate_request_id()
        timestamp = self._get_utc_timestamp()

        nsmap = {
            None: NAMESPACES['api'],
            'common': NAMESPACES['common'],
        }
        root = etree.Element("TokenExchangeRequest", nsmap=nsmap)

        root.append(self._build_basic_header(request_id, timestamp))
        root.append(self._build_user_element(request_id, timestamp))
        root.append(self._build_software_element())

        return etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True
        )

    def _decrypt_token(self, encrypted_token: str) -> str:
        """
        Decrypt the exchange token using AES-128-ECB.

        Per NAV specification, the exchange key (replacement_key) is a 32-character
        hex string representing 16 bytes for AES-128 encryption.

        Args:
            encrypted_token: Base64 encoded encrypted token

        Returns:
            Decrypted token string

        Raises:
            NavApiError: If decryption fails
        """
        try:
            # NAV exchange key is 32 hex characters = 16 bytes for AES-128
            key_str = self.credentials.replacement_key

            if len(key_str) == 32:
                # Try to interpret as hex string first (standard NAV format)
                try:
                    key_bytes = bytes.fromhex(key_str)
                    logger.debug("Using hex-decoded exchange key for AES-128")
                except ValueError:
                    # Fallback: use first 16 bytes of UTF-8 encoded string
                    key_bytes = key_str.encode('utf-8')[:16]
                    logger.warning("Exchange key is not valid hex, using UTF-8 encoding (may fail)")
            else:
                # Non-standard key length, use first 16 bytes
                key_bytes = key_str.encode('utf-8')[:16]
                logger.warning(f"Exchange key length is {len(key_str)}, expected 32. Using first 16 bytes.")

            # Ensure we have exactly 16 bytes for AES-128
            if len(key_bytes) != 16:
                raise NavApiError(
                    "INVALID_EXCHANGE_KEY",
                    f"Exchange key must be 16 bytes for AES-128, got {len(key_bytes)} bytes"
                )

            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decoded_token = base64.b64decode(encrypted_token)
            decrypted = cipher.decrypt(decoded_token)

            # Try PKCS7 unpadding first (standard padding scheme)
            try:
                decrypted = unpad(decrypted, AES.block_size)
                logger.debug("Successfully removed PKCS7 padding from token")
            except ValueError:
                # Not PKCS7 padded, try null-byte stripping
                logger.debug("Token not PKCS7 padded, using null-byte stripping")
                pass

            # Decode to string and strip null bytes and whitespace
            token = decrypted.decode('utf-8').rstrip('\x00').strip()

            if not token:
                raise NavApiError("EMPTY_TOKEN", "Decrypted token is empty")

            return token

        except NavApiError:
            raise
        except Exception as e:
            logger.error(f"Token decryption failed: {e}", exc_info=True)
            raise NavApiError("TOKEN_DECRYPTION_FAILED", f"Could not decrypt token: {str(e)}")

    def token_exchange(self) -> str:
        """
        Obtain a session token for write operations.

        Returns:
            Decrypted session token string
        """
        request_body = self._build_token_exchange_request()
        response = self._execute_with_retry("/tokenExchange", request_body)

        root = etree.fromstring(response)
        encoded_token = root.findtext(".//{%s}encodedExchangeToken" % NAMESPACES['api'])

        if not encoded_token:
            raise NavApiError("MISSING_TOKEN", "Response did not contain encodedExchangeToken")

        return self._decrypt_token(encoded_token)

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

    def _validate_sept_2025_rules(self, invoice_xml: bytes) -> List[str]:
        """
        Validate invoice against September 2025 blocking rules before submission.

        These validations will become BLOCKING errors in NAV starting Sept 15, 2025:
        - Error 435: VAT rate doesn't match tax number status
        - Error 734: VAT summary calculation mismatch
        - Error 1311: VAT line item inconsistency

        Args:
            invoice_xml: Decoded invoice XML bytes

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        try:
            root = etree.fromstring(invoice_xml)

            # Extract VAT summary totals
            vat_summary_total = 0.0
            line_item_vat_total = 0.0

            # Find VAT summary section
            for vat_rate_elem in root.findall(".//{%s}summaryByVatRate" % NAMESPACES.get('data', '')):
                vat_amount = vat_rate_elem.findtext(".//{%s}vatRateVatAmount" % NAMESPACES.get('data', ''))
                if vat_amount:
                    try:
                        vat_summary_total += float(vat_amount)
                    except ValueError:
                        pass

            # Also try without namespace for flexibility
            for vat_rate_elem in root.findall(".//summaryByVatRate"):
                vat_amount = vat_rate_elem.findtext(".//vatRateVatAmount")
                if vat_amount:
                    try:
                        vat_summary_total += float(vat_amount)
                    except ValueError:
                        pass

            # Find line items and validate VAT calculations
            for line_elem in root.findall(".//{%s}line" % NAMESPACES.get('data', '')):
                self._validate_line_item(line_elem, errors)

            for line_elem in root.findall(".//line"):
                line_item_vat_total += self._validate_line_item(line_elem, errors)

            # Validate VAT summary matches line items (Error 734)
            if vat_summary_total > 0 and line_item_vat_total > 0:
                difference = abs(vat_summary_total - line_item_vat_total)
                if difference > 1.0:  # 1 HUF tolerance
                    errors.append(
                        f"[734] VAT summary mismatch: line items total {line_item_vat_total:.2f}, "
                        f"summary shows {vat_summary_total:.2f} (diff: {difference:.2f} HUF)"
                    )

        except etree.XMLSyntaxError as e:
            logger.warning(f"Could not parse invoice XML for validation: {e}")

        return errors

    def _validate_line_item(self, line_elem: etree.Element, errors: List[str]) -> float:
        """
        Validate a single line item's VAT calculation.

        Args:
            line_elem: XML element for the line item
            errors: List to append error messages to

        Returns:
            VAT amount for this line item
        """
        vat_amount = 0.0

        try:
            # Try to extract values with and without namespace
            net_amount_str = (
                line_elem.findtext(".//{%s}lineNetAmount" % NAMESPACES.get('data', '')) or
                line_elem.findtext(".//lineNetAmount") or
                line_elem.findtext(".//{%s}lineNetAmountData/{%s}lineNetAmount" % (
                    NAMESPACES.get('data', ''), NAMESPACES.get('data', ''))) or
                "0"
            )

            vat_amount_str = (
                line_elem.findtext(".//{%s}lineVatAmount" % NAMESPACES.get('data', '')) or
                line_elem.findtext(".//lineVatAmount") or
                line_elem.findtext(".//{%s}lineVatData/{%s}lineVatAmount" % (
                    NAMESPACES.get('data', ''), NAMESPACES.get('data', ''))) or
                "0"
            )

            vat_rate_str = (
                line_elem.findtext(".//{%s}vatPercentage" % NAMESPACES.get('data', '')) or
                line_elem.findtext(".//vatPercentage") or
                "0"
            )

            net_amount = float(net_amount_str)
            vat_amount = float(vat_amount_str)
            vat_rate = float(vat_rate_str)

            # Validate calculation (Error 1311)
            if net_amount > 0 and vat_rate > 0:
                expected_vat = net_amount * (vat_rate / 100.0)
                difference = abs(expected_vat - vat_amount)

                if difference > 1.0:  # 1 HUF tolerance
                    line_number = line_elem.findtext(".//lineNumber") or "?"
                    errors.append(
                        f"[1311] Line {line_number} VAT error: {net_amount:.2f} * {vat_rate}% = "
                        f"{expected_vat:.2f}, but shows {vat_amount:.2f}"
                    )

        except (ValueError, TypeError) as e:
            logger.debug(f"Could not validate line item: {e}")

        return vat_amount

    def manage_invoice(
        self,
        invoice_operations: List[Dict[str, Any]],
        validate_sept_2025: bool = True
    ) -> str:
        """
        Submit invoices (create, modify, storno) to NAV.

        Args:
            invoice_operations: List of operation dicts containing 'index', 'operation', 'invoiceData' (base64)
            validate_sept_2025: If True, validate against Sept 2025 blocking rules before submission

        Returns:
            Transaction ID

        Raises:
            NavApiError: If validation fails or NAV returns an error
        """
        # 0. Pre-submission validation for September 2025 rules
        if validate_sept_2025:
            all_errors = []
            for op in invoice_operations:
                if op.get('operation') in ('CREATE', 'MODIFY'):
                    try:
                        invoice_xml = base64.b64decode(op['invoiceData'])
                        validation_errors = self._validate_sept_2025_rules(invoice_xml)
                        if validation_errors:
                            all_errors.extend([f"Invoice {op['index']}: {e}" for e in validation_errors])
                    except Exception as e:
                        logger.warning(f"Could not validate invoice {op['index']}: {e}")

            if all_errors:
                error_msg = "September 2025 validation failed:\n" + "\n".join(all_errors)
                raise NavApiError(
                    "SEPT_2025_VALIDATION",
                    error_msg,
                    "Pre-submission validation caught errors that will be blocking in Sept 2025"
                )

        # 1. Get token
        token = self.token_exchange()

        # 2. Build ManageInvoiceRequest
        request_id = self._generate_request_id()
        timestamp = self._get_utc_timestamp()

        # Calculate additional hash components for signature
        # SHA3-512(operation + invoiceData) for each operation
        concatenated_hashes = ""
        for op in invoice_operations:
            op_str = op['operation'] + op['invoiceData']
            concatenated_hashes += self._hash_sha3_512(op_str)

        nsmap = {
            None: NAMESPACES['api'],
            'common': NAMESPACES['common'],
        }
        root = etree.Element("ManageInvoiceRequest", nsmap=nsmap)

        root.append(self._build_basic_header(request_id, timestamp))
        root.append(self._build_user_element(request_id, timestamp, concatenated_hashes))
        root.append(self._build_software_element())

        etree.SubElement(root, "exchangeToken").text = token

        ops_list = etree.SubElement(root, "invoiceOperations")
        etree.SubElement(ops_list, "compressedContent").text = "false"

        for op in invoice_operations:
            op_elem = etree.SubElement(ops_list, "invoiceOperation")
            etree.SubElement(op_elem, "index").text = str(op['index'])
            etree.SubElement(op_elem, "invoiceOperation").text = op['operation'] # CREATE, MODIFY, STORNO
            etree.SubElement(op_elem, "invoiceData").text = op['invoiceData']

            # Note: electronicInvoiceHash would go here for electronic invoices

        request_body = etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=True)

        # 3. Send
        response = self._execute_with_retry("/manageInvoice", request_body)

        # 4. Parse transaction ID
        root_resp = etree.fromstring(response)
        transaction_id = root_resp.findtext(".//{%s}transactionId" % NAMESPACES['api'])

        if not transaction_id:
             # Check for error if no transaction ID
             self._check_response_for_errors(response)
             raise NavApiError("MISSING_TRX_ID", "Response did not contain transactionId")

        return transaction_id

    # =========================================================================
    # QUERY INVOICE DATA ENDPOINT
    # =========================================================================

    def _build_query_invoice_data_request(
        self,
        invoice_number: str,
        invoice_direction: str,
    ) -> bytes:
        """
        Build XML request for /queryInvoiceData endpoint.

        Args:
            invoice_number: The invoice number to query
            invoice_direction: "INBOUND" for incoming, "OUTBOUND" for outgoing

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

        # Add invoice number query
        invoice_query = etree.SubElement(root, "invoiceNumberQuery")
        etree.SubElement(invoice_query, "invoiceNumber").text = invoice_number
        etree.SubElement(invoice_query, "invoiceDirection").text = invoice_direction

        # Serialize with XML declaration
        return etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True
        )

    def _parse_invoice_data_response(self, response_xml: bytes) -> Dict[str, Any]:
        """
        Parse XML response from queryInvoiceData endpoint.

        Args:
            response_xml: Raw XML response bytes

        Returns:
            Dictionary with invoice data (including decoded base64 content)
        """
        root = etree.fromstring(response_xml)

        # Check for errors first
        self._check_response_for_errors(response_xml)

        result = {}

        # Extract invoice data (Base64)
        invoice_data_elem = root.find(".//{%s}invoiceData" % NAMESPACES['api'])
        if invoice_data_elem is not None and invoice_data_elem.text:
            result['invoice_data_base64'] = invoice_data_elem.text
            try:
                result['invoice_data_decoded'] = base64.b64decode(invoice_data_elem.text)
                # Try to parse the decoded XML to get some metadata if needed
                # decoded_xml = etree.fromstring(result['invoice_data_decoded'])
                # result['supplier_name'] = ...
            except Exception as e:
                logger.warning(f"Failed to decode invoice data: {e}")

        # Extract audit data
        audit_data = root.find(".//{%s}auditData" % NAMESPACES['api'])
        if audit_data is not None:
             result['insDate'] = self._get_text(audit_data, "insDate")
             result['originalRequestVersion'] = self._get_text(audit_data, "originalRequestVersion")
             result['id'] = self._get_text(audit_data, "id") # Transaction ID
             result['electronicInvoiceHash'] = self._get_text(audit_data, "electronicInvoiceHash")

        return result

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
        # Also check for funcCode without namespace if not found
        if func_code is None:
             func_code = root.find(".//funcCode")

        if func_code is not None and func_code.text and func_code.text != "OK":
            # errorCode and message are siblings of funcCode (inside result element)

            error_code = self._get_text_recursive(root, "errorCode", "UNKNOWN")
            error_msg = self._get_text_recursive(root, "message", "Unknown error")
            tech_msg = self._get_text_recursive(root, "technicalDetails", "")

            raise NavApiError(error_code, error_msg, tech_msg)

    def _get_text_recursive(self, element: etree.Element, tag: str, default: str = "") -> str:
        """Safely extract text from descendant element."""
        # Try simple recursive search
        child = element.find(".//" + tag)
        if child is not None and child.text:
            return child.text.strip()

        # Try with namespaces
        for ns in NAMESPACES.values():
            child = element.find(".//{%s}%s" % (ns, tag))
            if child is not None and child.text:
                return child.text.strip()
        return default

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
                # Enforce rate limiting before each request
                self._enforce_rate_limit()

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

    def query_invoice_data(
        self,
        invoice_number: str,
        invoice_direction: str = "INBOUND"
    ) -> Dict[str, Any]:
        """
        Retrieve complete invoice data by invoice number.

        Args:
            invoice_number: The invoice number to retrieve
            invoice_direction: "INBOUND" or "OUTBOUND"

        Returns:
            Dictionary containing 'invoice_data_decoded' (bytes) and other metadata
        """
        request_body = self._build_query_invoice_data_request(
            invoice_number=invoice_number,
            invoice_direction=invoice_direction
        )

        response = self._execute_with_retry("/queryInvoiceData", request_body)
        return self._parse_invoice_data_response(response)

    def query_incoming_invoices(
        self,
        issue_date_from: str,
        issue_date_to: str,
        page: int = 1,
        fetch_all_pages: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Query incoming (inbound) invoices from NAV for the specified date range.

        This uses queryInvoiceDigest to get the list of invoices.

        Args:
            issue_date_from: Start date in YYYY-MM-DD format
            issue_date_to: End date in YYYY-MM-DD format
            page: Starting page number (1-based)
            fetch_all_pages: If True, automatically fetch all pages

        Returns:
            List of invoice digest dictionaries.
        """
        return self.query_invoice_digest(
            invoice_direction="INBOUND",
            issue_date_from=issue_date_from,
            issue_date_to=issue_date_to,
            page=page,
            fetch_all_pages=fetch_all_pages
        )

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
        return self.query_invoice_digest(
            invoice_direction="OUTBOUND",
            issue_date_from=issue_date_from,
            issue_date_to=issue_date_to,
            page=page,
            fetch_all_pages=fetch_all_pages
        )

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
        invoice_category: Optional[str] = None,
        relational_params: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> bytes:
        """
        Build XML request for /queryInvoiceDigest endpoint.

        Args:
            invoice_direction: "INBOUND" or "OUTBOUND"
            issue_date_from: Start date (YYYY-MM-DD)
            issue_date_to: End date (YYYY-MM-DD)
            page: Page number (1-based)
            supplier_tax_number: Optional filter
            invoice_category: Optional filter
            relational_params: Dict of relational queries, e.g.:
                {'invoiceNetAmount': {'op': 'GT', 'value': 1000}}

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
        # Note: In a full implementation, mandatory params could be one of multiple choices.
        # Here we simplify to always use invoiceIssueDate as per typical usage.
        invoice_query_params = etree.SubElement(root, "invoiceQueryParams")
        mandatory_params = etree.SubElement(invoice_query_params, "mandatoryQueryParams")
        issue_date = etree.SubElement(mandatory_params, "invoiceIssueDate")
        etree.SubElement(issue_date, "dateFrom").text = issue_date_from
        etree.SubElement(issue_date, "dateTo").text = issue_date_to

        # Add additional query params
        if supplier_tax_number or invoice_category:
            additional_params = etree.SubElement(invoice_query_params, "additionalQueryParams")

            if supplier_tax_number:
                etree.SubElement(additional_params, "supplierTaxNumber").text = supplier_tax_number

            if invoice_category:
                etree.SubElement(additional_params, "invoiceCategory").text = invoice_category

        # Add relational query params
        if relational_params:
            relational_elem = etree.SubElement(invoice_query_params, "relationalQueryParams")
            for field, criteria in relational_params.items():
                field_elem = etree.SubElement(relational_elem, field)
                etree.SubElement(field_elem, "queryOperator").text = criteria.get('op', 'EQ')
                etree.SubElement(field_elem, "queryValue").text = str(criteria.get('value', ''))

        return etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True
        )

    def _parse_invoice_digest_response(self, response_xml: bytes) -> tuple[List[Dict[str, Any]], int]:
        """
        Parse XML response from queryInvoiceDigest endpoint.

        Returns:
            Tuple of (list of digest dicts, total_available_pages)
        """
        root = etree.fromstring(response_xml)
        digests = []

        # Parse pagination info
        try:
            available_pages = int(self._get_text(root, "availablePage", "0"))
        except ValueError:
            available_pages = 0

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

        return digests, available_pages

    def query_invoice_digest(
        self,
        invoice_direction: str,
        issue_date_from: str,
        issue_date_to: str,
        page: int = 1,
        fetch_all_pages: bool = True,
        supplier_tax_number: Optional[str] = None,
        invoice_category: Optional[str] = None,
        relational_params: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Query invoice digest (summary) from NAV.

        Args:
            relational_params: Optional dict for advanced filtering (e.g. amount > X)
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
                invoice_category=invoice_category,
                relational_params=relational_params
            )

            response = self._execute_with_retry("/queryInvoiceDigest", request_body)
            page_digests, total_pages = self._parse_invoice_digest_response(response)

            all_digests.extend(page_digests)

            if not fetch_all_pages or len(page_digests) == 0:
                break

            # If we know total pages, use that
            if total_pages > 0:
                if current_page >= total_pages:
                    break
            # Fallback to item count heuristic
            elif len(page_digests) < 100:
                break

            current_page += 1
            time.sleep(1.1)

        return all_digests

    # =========================================================================
    # QUERY TRANSACTION STATUS ENDPOINT
    # =========================================================================

    def _build_query_transaction_status_request(
        self,
        transaction_id: str,
        return_original_request: bool = False
    ) -> bytes:
        """
        Build XML request for /queryTransactionStatus endpoint.

        Args:
            transaction_id: The transaction ID to query
            return_original_request: Whether to include original request XML

        Returns:
            UTF-8 encoded XML request body
        """
        request_id = self._generate_request_id()
        timestamp = self._get_utc_timestamp()

        nsmap = {
            None: NAMESPACES['api'],
            'common': NAMESPACES['common'],
        }
        root = etree.Element("QueryTransactionStatusRequest", nsmap=nsmap)

        root.append(self._build_basic_header(request_id, timestamp))
        root.append(self._build_user_element(request_id, timestamp))
        root.append(self._build_software_element())

        etree.SubElement(root, "transactionId").text = transaction_id
        etree.SubElement(root, "returnOriginalRequest").text = str(return_original_request).lower()

        return etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True
        )

    def _parse_transaction_status_response(self, response_xml: bytes) -> Dict[str, Any]:
        """
        Parse XML response from queryTransactionStatus endpoint.
        """
        root = etree.fromstring(response_xml)
        self._check_response_for_errors(response_xml)

        result = {
            "processingResults": []
        }

        processing_results = root.find(".//{%s}processingResultList" % NAMESPACES['api'])
        if processing_results is not None:
            for proc_result in processing_results.findall(".//{%s}processingResult" % NAMESPACES['api']):
                item = {
                    "index": int(self._get_text(proc_result, "index", "0")),
                    "batchIndex": int(self._get_text(proc_result, "batchIndex", "0")),
                    "invoiceStatus": self._get_text(proc_result, "invoiceStatus", "UNKNOWN"),
                    "businessValidationMessages": []
                }

                # Parse validation messages if any
                msgs = proc_result.findall(".//{%s}businessValidationResult" % NAMESPACES['api'])
                for msg in msgs:
                     item["businessValidationMessages"].append({
                         "validationResultCode": self._get_text(msg, "validationResultCode", ""),
                         "validationErrorCode": self._get_text(msg, "validationErrorCode", ""),
                         "message": self._get_text(msg, "message", ""),
                         "pointer": self._get_text(msg, "pointer", "")
                     })

                result["processingResults"].append(item)

        return result

    def query_transaction_status(
        self,
        transaction_id: str,
        return_original_request: bool = False
    ) -> Dict[str, Any]:
        """
        Check status of a submitted transaction.

        Args:
            transaction_id: ID returned from manageInvoice
            return_original_request: Return original XML if available

        Returns:
            Dictionary with processing results and validation messages
        """
        request_body = self._build_query_transaction_status_request(
            transaction_id=transaction_id,
            return_original_request=return_original_request
        )

        response = self._execute_with_retry("/queryTransactionStatus", request_body)
        return self._parse_transaction_status_response(response)

    # =========================================================================
    # QUERY TRANSACTION LIST ENDPOINT
    # =========================================================================

    def _build_query_transaction_list_request(
        self,
        date_time_from: str,
        date_time_to: str,
        page: int = 1,
        invoice_direction: Optional[str] = None,
        transaction_status: Optional[str] = None,
        request_status: Optional[str] = None,
    ) -> bytes:
        """
        Build XML request for /queryTransactionList endpoint.

        This endpoint is used to recover from timeout situations by listing
        all transactions within a time range.

        Args:
            date_time_from: Start datetime (ISO format: 2024-01-15T00:00:00Z)
            date_time_to: End datetime (ISO format: 2024-01-15T23:59:59Z)
            page: Page number (1-based)
            invoice_direction: Optional filter: "INBOUND" or "OUTBOUND"
            transaction_status: Optional filter: "RECEIVED", "PROCESSING", "DONE", "ABORTED"
            request_status: Optional filter: "RECEIVED", "PROCESSING", "SAVED", "FINISHED", "NOTIFIED"

        Returns:
            UTF-8 encoded XML request body
        """
        request_id = self._generate_request_id()
        timestamp = self._get_utc_timestamp()

        nsmap = {
            None: NAMESPACES['api'],
            'common': NAMESPACES['common'],
        }
        root = etree.Element("QueryTransactionListRequest", nsmap=nsmap)

        root.append(self._build_basic_header(request_id, timestamp))
        root.append(self._build_user_element(request_id, timestamp))
        root.append(self._build_software_element())

        # Add page number
        etree.SubElement(root, "page").text = str(page)

        # Add mandatory date range
        ins_date = etree.SubElement(root, "insDate")
        etree.SubElement(ins_date, "dateTimeFrom").text = date_time_from
        etree.SubElement(ins_date, "dateTimeTo").text = date_time_to

        # Add optional filters
        if invoice_direction:
            etree.SubElement(root, "invoiceDirection").text = invoice_direction

        if transaction_status:
            etree.SubElement(root, "transactionStatus").text = transaction_status

        if request_status:
            etree.SubElement(root, "requestStatus").text = request_status

        return etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True
        )

    def _parse_transaction_list_response(self, response_xml: bytes) -> tuple[List[Dict[str, Any]], int]:
        """
        Parse XML response from queryTransactionList endpoint.

        Returns:
            Tuple of (list of transaction dicts, total_available_pages)
        """
        root = etree.fromstring(response_xml)
        self._check_response_for_errors(response_xml)

        transactions = []

        # Parse pagination info
        try:
            available_pages = int(self._get_text(root, "availablePage", "0"))
        except ValueError:
            available_pages = 0

        # Find all transaction elements
        for tx_elem in root.findall(".//{%s}transaction" % NAMESPACES['api']):
            try:
                transaction = {
                    "transactionId": self._get_text(tx_elem, "transactionId", ""),
                    "requestStatus": self._get_text(tx_elem, "requestStatus", ""),
                    "technicalAnnulment": self._get_text(tx_elem, "technicalAnnulment", "false") == "true",
                    "originalRequestVersion": self._get_text(tx_elem, "originalRequestVersion", ""),
                    "itemCount": int(self._get_text(tx_elem, "itemCount", "0")),
                    "insDate": self._get_text(tx_elem, "insDate", ""),
                }
                transactions.append(transaction)

            except (ValueError, AttributeError) as e:
                logger.warning(f"Could not parse transaction element: {e}")
                continue

        return transactions, available_pages

    def query_transaction_list(
        self,
        date_time_from: str,
        date_time_to: str,
        page: int = 1,
        fetch_all_pages: bool = True,
        invoice_direction: Optional[str] = None,
        transaction_status: Optional[str] = None,
        request_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query list of transactions within a time range.

        This endpoint is essential for timeout recovery - if a manageInvoice
        request times out, you can use this to find the transaction ID and
        check its status.

        Args:
            date_time_from: Start datetime (ISO format: 2024-01-15T00:00:00Z)
            date_time_to: End datetime (ISO format: 2024-01-15T23:59:59Z)
            page: Starting page number (1-based)
            fetch_all_pages: If True, automatically fetch all pages
            invoice_direction: Optional filter: "INBOUND" or "OUTBOUND"
            transaction_status: Optional filter: "RECEIVED", "PROCESSING", "DONE", "ABORTED"
            request_status: Optional filter: "RECEIVED", "PROCESSING", "SAVED", "FINISHED", "NOTIFIED"

        Returns:
            List of transaction dictionaries with transactionId, requestStatus, etc.
        """
        all_transactions: List[Dict[str, Any]] = []
        current_page = page

        while True:
            request_body = self._build_query_transaction_list_request(
                date_time_from=date_time_from,
                date_time_to=date_time_to,
                page=current_page,
                invoice_direction=invoice_direction,
                transaction_status=transaction_status,
                request_status=request_status,
            )

            response = self._execute_with_retry("/queryTransactionList", request_body)
            transactions, available_pages = self._parse_transaction_list_response(response)

            all_transactions.extend(transactions)

            if not fetch_all_pages or current_page >= available_pages:
                break

            current_page += 1

        return all_transactions

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
            gross = inv.get('invoiceNetAmount', 0) + inv.get('invoiceVatAmount', 0)
            print(f"  - {inv['invoiceNumber']}: {inv['supplierName']} "
                  f"({gross:,.0f} {inv.get('currency', 'HUF')})")

        if len(invoices) > 5:
            print(f"  ... and {len(invoices) - 5} more")

        # Example of fetching full data for the first invoice
        if invoices:
            first_inv_num = invoices[0]['invoiceNumber']
            print(f"\nFetching full data for {first_inv_num}...")
            full_data = client.query_invoice_data(first_inv_num)
            print("✓ Full data retrieved (size: %d bytes)" % len(full_data.get('invoice_data_decoded', b'')))

    except NavApiError as e:
        print(f"✗ NAV API Error: {e}")
        if e.technical_message:
            print(f"  Technical details: {e.technical_message}")
    except Exception as e:
        print(f"✗ Error: {e}")
