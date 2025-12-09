# Complete Technical Guide: Hungarian NAV Online Számla API Integration with Python

Companies operating in Hungary must report invoice data in real-time to NAV (National Tax and Customs Administration) through the Online Számla system. This guide provides **complete technical specifications for API v3.0** query operations, Python implementation approaches, and practical developer guidance for retrieving your own invoice data from the NAV system. The API is REST-based with XML payloads, requires SHA3-512 cryptographic signatures, and offers both test and production environments.

## Understanding the NAV Online Invoice system architecture

The Hungarian Online Számla system mandates real-time reporting of all B2B, B2C, intra-community, and export invoices with no minimum threshold. Since **May 15, 2025, only API v3.0 is supported**—earlier versions are no longer accepted. The system operates on separate test and production environments, each requiring independent registration and credentials.

The production API endpoint is `https://api.onlineszamla.nav.gov.hu/invoiceService/v3/`, while testing occurs at `https://api-test.onlineszamla.nav.gov.hu/invoiceService/v3/`. All requests use XML with specific NAV-defined schemas and require cryptographic authentication using SHA-512 for passwords and SHA3-512 for request signatures.

NAV provides official XSD schemas at their GitHub repository (nav-gov-hu/Online-Invoice) covering four main schema files: `invoiceApi.xsd` for API request/response structures, `invoiceData.xsd` for invoice business data, `invoiceBase.xsd` for shared base types, and `invoiceAnnulment.xsd` for technical annulment structures. The namespaces for v3.0 are:

```xml
xmlns="http://schemas.nav.gov.hu/OSA/3.0/api"
xmlns:data="http://schemas.nav.gov.hu/OSA/3.0/data"
xmlns:base="http://schemas.nav.gov.hu/OSA/3.0/base"
xmlns:common="http://schemas.nav.gov.hu/NTCA/1.0/common"
```

## Registration and technical user setup requires four credential components

Before making API calls, you must register on the NAV portal and create a technical user. Navigate to https://onlineszamla.nav.gov.hu/ (production) or https://onlineszamla-test.nav.gov.hu/ (test) and authenticate via the KAÜ (Central Authentication Agent) using your Ügyfélkapu+ credentials with two-factor authentication through the DÁP mobile app or an authenticator app.

After completing taxpayer registration with your company's contact information, create a technical user by navigating to the "Felhasználók" (Users) menu and selecting "Technikai felhasználó" (Technical User). Assign the **"Számlák lekérdezése"** (Query Invoices) permission for invoice retrieval operations. Upon saving and clicking "Kulcsgenerálás" (Generate Key), you receive four critical credentials:

The **login** is a system-generated 15-character alphanumeric username. The **password** is user-defined during creation and must be stored securely as it cannot be recovered. The **XML Aláírókulcs (Signature Key)** is used for calculating the `requestSignature` field using SHA3-512. The **XML Cserekulcs (Exchange Key)** is used for AES-128-ECB decryption of exchange tokens. Test environment registration is completely separate from production—credentials do not transfer between environments.

## Authentication flow combines hashed credentials with token exchange

Every API request includes a user authentication block containing your hashed credentials and a cryptographic signature. The password is hashed using SHA-512, while the request signature uses SHA3-512. Here's the standard request structure:

```xml
<common:user>
  <common:login>TECHNICALUSER123</common:login>
  <common:passwordHash cryptoType="SHA-512">UPPERCASE_SHA512_HASH</common:passwordHash>
  <common:taxNumber>12345678</common:taxNumber>
  <common:requestSignature cryptoType="SHA3-512">CALCULATED_SHA3512</common:requestSignature>
</common:user>
```

The `requestSignature` for query operations is calculated as `SHA3-512(requestId + timestamp + signatureKey)` where the timestamp format removes all separators, becoming `YYYYMMDDHHmmss`. For invoice submission operations, additional hash components for each invoice are concatenated before the final hash.

For `manageInvoice` operations requiring write access, you must first call `/tokenExchange` to obtain an encrypted token, then decrypt it using AES-128-ECB with your exchange key. The token is valid for **5 minutes** and is single-use. For read-only query operations like `queryInvoiceData`, token exchange is not required—direct authenticated requests work.

## Three core endpoints handle invoice data retrieval

### queryInvoiceData retrieves complete invoice content

This endpoint returns full invoice data by invoice number, available for both outbound (supplier) and inbound (customer) queries. The request specifies the invoice number, direction (OUTBOUND or INBOUND), and optionally a batch index for batch invoices:

```xml
<QueryInvoiceDataRequest xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
  <common:header>
    <common:requestId>UNIQUE_REQUEST_ID_30CHAR</common:requestId>
    <common:timestamp>2024-12-09T10:30:00.000Z</common:timestamp>
    <common:requestVersion>3.0</common:requestVersion>
    <common:headerVersion>1.0</common:headerVersion>
  </common:header>
  <common:user>...</common:user>
  <software>...</software>
  <invoiceNumberQuery>
    <invoiceNumber>INV-2024-001</invoiceNumber>
    <invoiceDirection>OUTBOUND</invoiceDirection>
  </invoiceNumberQuery>
</QueryInvoiceDataRequest>
```

The response contains BASE64-encoded invoice data (optionally GZIP-compressed when `compressedContentIndicator` is true), audit metadata including insertion timestamp and transaction ID, and for electronic invoices, a SHA3-512 hash in the `electronicInvoiceHash` field.

### queryInvoiceDigest enables parametric search with pagination

For searching invoices by date ranges, amounts, payment methods, or other criteria, `queryInvoiceDigest` returns summary information rather than full content. This is essential for discovering invoices before fetching complete data:

```xml
<QueryInvoiceDigestRequest xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
  <common:header>...</common:header>
  <common:user>...</common:user>
  <software>...</software>
  <page>1</page>
  <invoiceDirection>OUTBOUND</invoiceDirection>
  <invoiceQueryParams>
    <mandatoryQueryParams>
      <invoiceIssueDate>
        <dateFrom>2024-01-01</dateFrom>
        <dateTo>2024-12-31</dateTo>
      </invoiceIssueDate>
    </mandatoryQueryParams>
    <additionalQueryParams>
      <currency>HUF</currency>
      <invoiceCategory>NORMAL</invoiceCategory>
    </additionalQueryParams>
    <relationalQueryParams>
      <invoiceNetAmount>
        <queryOperator>GTE</queryOperator>
        <queryValue>100000</queryValue>
      </invoiceNetAmount>
    </relationalQueryParams>
  </invoiceQueryParams>
</QueryInvoiceDigestRequest>
```

The mandatory query parameters must include either `invoiceIssueDate`, `insDate` (insertion date), or `originalInvoiceNumber`. Relational operators include EQ, GT, GTE, LT, and LTE for numeric comparisons. The response includes `availablePage` indicating total pages for pagination.

### queryTransactionStatus tracks submission processing

After submitting invoices via `manageInvoice`, this endpoint monitors processing status using the returned transaction ID. Status values progress through **RECEIVED** (queued), **PROCESSING** (under validation), **SAVED** (accepted, queryable), **DONE** (complete), or **ABORTED** (failed with errors). The response includes detailed validation messages with pointers to specific problematic elements.

## Python implementation requires custom development or community libraries

NAV provides no official Python SDK—only XSD schemas and documentation at their GitHub repository. The most mature community option is `ois_api_client`, installable via `pip install ois_api_client`, though it primarily supports API v2 and may need adaptation for v3.0. For production deployments, custom implementation provides the most control and v3.0 compatibility.

Here's a complete Python implementation for authentication and invoice querying:

```python
import hashlib
import requests
from lxml import etree
from datetime import datetime, timezone
import uuid
import base64
from Crypto.Cipher import AES

class NAVOnlineInvoice:
    def __init__(self, login: str, password: str, tax_number: str,
                 sign_key: str, exchange_key: str, software_info: dict,
                 test_mode: bool = True):
        self.login = login
        self.password = password
        self.tax_number = tax_number[:8]  # First 8 digits only
        self.sign_key = sign_key
        self.exchange_key = exchange_key
        self.software = software_info
        self.base_url = (
            "https://api-test.onlineszamla.nav.gov.hu/invoiceService/v3"
            if test_mode else
            "https://api.onlineszamla.nav.gov.hu/invoiceService/v3"
        )
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/xml',
            'Accept': 'application/xml'
        })
    
    def _generate_password_hash(self) -> str:
        """SHA-512 hash of password, uppercase."""
        return hashlib.sha512(self.password.encode('utf-8')).hexdigest().upper()
    
    def _generate_request_signature(self, request_id: str, timestamp: datetime) -> str:
        """SHA3-512 signature for non-invoice operations."""
        ts_string = timestamp.strftime('%Y%m%d%H%M%S')
        buffer = f"{request_id}{ts_string}{self.sign_key}"
        return hashlib.sha3_512(buffer.encode('utf-8')).hexdigest().upper()
    
    def _build_request_xml(self, operation: str, body_builder: callable) -> bytes:
        """Construct complete request XML with authentication."""
        NSMAP = {
            None: "http://schemas.nav.gov.hu/OSA/3.0/api",
            'common': "http://schemas.nav.gov.hu/NTCA/1.0/common"
        }
        
        request_id = f"REQ{uuid.uuid4().hex[:20].upper()}"
        timestamp = datetime.now(timezone.utc)
        
        root = etree.Element(f"{operation}Request", nsmap=NSMAP)
        
        # Header
        header = etree.SubElement(root, "{http://schemas.nav.gov.hu/NTCA/1.0/common}header")
        etree.SubElement(header, "{http://schemas.nav.gov.hu/NTCA/1.0/common}requestId").text = request_id
        etree.SubElement(header, "{http://schemas.nav.gov.hu/NTCA/1.0/common}timestamp").text = timestamp.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        etree.SubElement(header, "{http://schemas.nav.gov.hu/NTCA/1.0/common}requestVersion").text = "3.0"
        etree.SubElement(header, "{http://schemas.nav.gov.hu/NTCA/1.0/common}headerVersion").text = "1.0"
        
        # User authentication
        user = etree.SubElement(root, "{http://schemas.nav.gov.hu/NTCA/1.0/common}user")
        etree.SubElement(user, "{http://schemas.nav.gov.hu/NTCA/1.0/common}login").text = self.login
        
        pw_hash = etree.SubElement(user, "{http://schemas.nav.gov.hu/NTCA/1.0/common}passwordHash")
        pw_hash.text = self._generate_password_hash()
        pw_hash.set("cryptoType", "SHA-512")
        
        etree.SubElement(user, "{http://schemas.nav.gov.hu/NTCA/1.0/common}taxNumber").text = self.tax_number
        
        req_sig = etree.SubElement(user, "{http://schemas.nav.gov.hu/NTCA/1.0/common}requestSignature")
        req_sig.text = self._generate_request_signature(request_id, timestamp)
        req_sig.set("cryptoType", "SHA3-512")
        
        # Software info
        software = etree.SubElement(root, "software")
        etree.SubElement(software, "softwareId").text = self.software['id']
        etree.SubElement(software, "softwareName").text = self.software['name']
        etree.SubElement(software, "softwareOperation").text = self.software['operation']
        etree.SubElement(software, "softwareMainVersion").text = self.software['version']
        etree.SubElement(software, "softwareDevName").text = self.software['dev_name']
        etree.SubElement(software, "softwareDevContact").text = self.software['dev_contact']
        etree.SubElement(software, "softwareDevCountryCode").text = self.software.get('country', 'HU')
        
        # Operation-specific body
        body_builder(root)
        
        return etree.tostring(root, pretty_print=True, xml_declaration=True, encoding='UTF-8')
    
    def query_invoice_digest(self, date_from: str, date_to: str, 
                             direction: str = 'OUTBOUND', page: int = 1) -> dict:
        """Query invoice summaries by date range."""
        def body_builder(root):
            etree.SubElement(root, "page").text = str(page)
            etree.SubElement(root, "invoiceDirection").text = direction
            
            params = etree.SubElement(root, "invoiceQueryParams")
            mandatory = etree.SubElement(params, "mandatoryQueryParams")
            issue_date = etree.SubElement(mandatory, "invoiceIssueDate")
            etree.SubElement(issue_date, "dateFrom").text = date_from
            etree.SubElement(issue_date, "dateTo").text = date_to
        
        xml_request = self._build_request_xml("QueryInvoiceDigest", body_builder)
        response = self.session.post(f"{self.base_url}/queryInvoiceDigest", data=xml_request)
        return self._parse_response(response, 'digest')
    
    def query_invoice_data(self, invoice_number: str, 
                           direction: str = 'OUTBOUND') -> dict:
        """Retrieve complete invoice data by number."""
        def body_builder(root):
            query = etree.SubElement(root, "invoiceNumberQuery")
            etree.SubElement(query, "invoiceNumber").text = invoice_number
            etree.SubElement(query, "invoiceDirection").text = direction
        
        xml_request = self._build_request_xml("QueryInvoiceData", body_builder)
        response = self.session.post(f"{self.base_url}/queryInvoiceData", data=xml_request)
        return self._parse_response(response, 'data')
    
    def _parse_response(self, response: requests.Response, response_type: str) -> dict:
        """Parse XML response into dictionary."""
        root = etree.fromstring(response.content)
        
        # Strip namespaces for easier parsing
        for elem in root.iter():
            if '}' in elem.tag:
                elem.tag = elem.tag.split('}', 1)[1]
        
        result = {
            'func_code': root.findtext('.//funcCode'),
            'error_code': root.findtext('.//errorCode'),
            'message': root.findtext('.//message'),
            'raw_response': response.content
        }
        
        if response_type == 'digest':
            result['current_page'] = root.findtext('.//currentPage')
            result['available_pages'] = root.findtext('.//availablePage')
            result['digests'] = []
            for digest in root.findall('.//invoiceDigest'):
                result['digests'].append({
                    'invoice_number': digest.findtext('invoiceNumber'),
                    'issue_date': digest.findtext('invoiceIssueDate'),
                    'supplier_name': digest.findtext('supplierName'),
                    'customer_name': digest.findtext('customerName'),
                    'net_amount': digest.findtext('invoiceNetAmount'),
                    'vat_amount': digest.findtext('invoiceVatAmount'),
                    'currency': digest.findtext('currency')
                })
        
        elif response_type == 'data':
            invoice_data = root.findtext('.//invoiceData')
            if invoice_data:
                result['invoice_data_base64'] = invoice_data
                result['invoice_data_decoded'] = base64.b64decode(invoice_data)
        
        return result


# Usage example
software_config = {
    'id': 'HU12345678-MYSOFT01',
    'name': 'My Invoice System',
    'operation': 'LOCAL_SOFTWARE',
    'version': '1.0',
    'dev_name': 'My Company Ltd',
    'dev_contact': 'dev@mycompany.hu'
}

client = NAVOnlineInvoice(
    login='TECH_USER_LOGIN',
    password='your_password',
    tax_number='12345678',
    sign_key='your-signature-key-here',
    exchange_key='your-exchange-key',
    software_info=software_config,
    test_mode=True
)

# Query invoices from 2024
digests = client.query_invoice_digest('2024-01-01', '2024-12-31')
for invoice in digests.get('digests', []):
    print(f"{invoice['invoice_number']}: {invoice['net_amount']} {invoice['currency']}")
    
    # Fetch full invoice data
    full_data = client.query_invoice_data(invoice['invoice_number'])
```

## Testing environment enables risk-free development

The test environment at `https://api-test.onlineszamla.nav.gov.hu` is functionally identical to production but accepts any tax number format without validation against real registrations. Register separately at the test portal, create test technical users, and point your application to the test API URL during development.

Key differences from production: test data is treated as fictitious with no penalties for errors, though all rate limits and authentication requirements remain enforced. The test portal frontend at https://onlineszamla-test.nav.gov.hu/ allows you to verify submitted test invoices visually.

## Rate limits and operational constraints affect implementation design

The API enforces **1 request per second per IP address** on rate-limited endpoints. Additional requests receive cumulative 4-second delays, and requests exceeding 60 seconds total queue time are terminated server-side. The rate-limited endpoints include tokenExchange, manageInvoice, queryInvoiceData, queryInvoiceStatus, and queryTaxpayer.

Other critical limits include: maximum **100 invoices per request**, maximum HTTP body of **10 MB** compressed, maximum uncompressed invoice size of **15 MB**, token validity of **5 minutes**, timestamp tolerance of **±1 day** from server UTC time, synchronous timeout of 5 seconds, and absolute timeout of 60 seconds.

Implement exponential backoff for retries, use `queryTransactionList` to verify submissions when responses timeout, and never resubmit without first checking if the original transaction succeeded.

## Common implementation pitfalls have known solutions

The most frequent error is **INVALID_REQUEST_SIGNATURE**, typically caused by incorrect timestamp formatting (must be UTC without separators for signature calculation but ISO 8601 with separators in the XML), using SHA-512 instead of SHA3-512 for signatures, or incorrect concatenation order. Verify your signature matches the documented formula exactly.

Character encoding issues arise because the API uses UTF-8 regardless of request encoding declarations—ensure your XML generation library outputs proper UTF-8. Date handling problems occur when using local time instead of UTC; always use timezone-aware datetime objects.

VAT-related validations are becoming stricter: from **September 15, 2025**, 15 current warnings become blocking errors, including mismatches between `customerVatStatus` and provided tax numbers. When `customerVatStatus` is `DOMESTIC`, a Hungarian tax number is mandatory; intra-community transactions require buyer type `OTHER`.

## September 2025 brings significant validation changes

Starting September 15, 2025, previously tolerated data inconsistencies will block invoice submissions. Testing for these changes begins September 1, 2025. The affected validations include tax number format errors, VAT status inconsistencies with tax number types, currency exchange data mismatches, and incorrect buyer status for intra-community supplies.

Three new warning codes (435, 734, 1311) address VAT rate inconsistencies between line items and summaries. Proactively audit your invoice generation logic to ensure VAT calculations match between detail lines and summary sections, and that customer VAT status correctly reflects the tax number format provided.

Penalty exposure increased significantly in August 2024 to **up to HUF 1,000,000 per invoice** for missing or incorrect data reporting. Since January 2025, NAV actively compares Online Számla data against VAT returns, making accurate real-time reporting essential for compliance.

## Essential dependencies and security requirements

Your Python implementation requires these packages:

```
requests>=2.25.0
lxml>=4.6.0
pycryptodome>=3.10.0  # For AES-128-ECB token decryption
```

Python 3.6+ includes native SHA3 support in `hashlib`—no additional cryptographic libraries are needed for signature generation. TLS 1.2 is mandatory for all connections; older systems without TLS 1.2 support cannot connect to the API.

Store credentials securely using environment variables or secret management systems—never commit technical user passwords or signing keys to source control. Implement comprehensive logging of all request IDs and timestamps for audit purposes, and retain complete request/response XML for at least 8 years per Hungarian accounting law requirements.

## Conclusion

Successful NAV Online Számla integration requires careful attention to cryptographic authentication (SHA-512 passwords, SHA3-512 signatures), proper XML namespace handling, and understanding the API's rate limiting behavior. Start development in the test environment with dedicated test credentials, validate your XML against the official XSD schemas, and implement robust retry logic with transaction verification before promoting to production. The September 2025 validation changes make proactive testing against the new rules essential for uninterrupted invoice reporting.