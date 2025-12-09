# Comprehensive Testing Framework for NAV Online Számla API Implementation

**Fifteen new blocking errors take effect September 15, 2025**, fundamentally changing what passes NAV validation. This testing framework provides executable test cases covering authentication, queries, error handling, security, and the critical September 2025 regression scenarios—ensuring your implementation survives production deployment.

The Hungarian NAV Online Számla API version 3.0 requires rigorous validation before production use. Organizations face **penalties up to HUF 1,000,000 per invoice** for incorrect or missing data reporting. This guide transforms technical specifications into actionable test cases with specific validation criteria.

---

## Pre-deployment validation checklist

Before any production deployment, systematically verify each component in sequence. Failed authentication blocks all subsequent operations, making credential validation the critical first gate.

### Authentication and cryptographic validation

| Check | Validation Method | Pass Criteria |
|-------|------------------|---------------|
| SHA-512 password hash | Compare computed hash with test vector | Uppercase hex, 128 characters |
| SHA3-512 request signature | Validate against known input/output pairs | Uppercase hex, matches NAV calculation |
| Timestamp UTC conversion | Submit request, verify no INVALID_TIMESTAMP | Response funcCode = OK |
| Technical user credentials | tokenExchange call | Successful token returned |
| Software registration ID | Any API call | No INVALID_SOFTWARE_ID error |
| Signing key format | Signature calculation | Min 8 chars, upper/lower/numbers |

### XML schema validation requirements

Download current XSD files from `https://github.com/nav-gov-hu/Online-Invoice/tree/master/src/schemas`:
- `invoiceApi.xsd` (OSA/3.0/api namespace)
- `invoiceData.xsd` (OSA/3.0/data namespace)
- `common.xsd` (NTCA/1.0/common namespace)
- `invoiceBase.xsd` (OSA/3.0/base namespace)

**Validation command**: `xmllint --schema invoiceApi.xsd request.xml --noout`

### API endpoint connectivity verification

| Endpoint | Test Environment | Production Environment |
|----------|-----------------|----------------------|
| Base URL | api-test.onlineszamla.nav.gov.hu | api.onlineszamla.nav.gov.hu |
| Context | /invoiceService/v3 | /invoiceService/v3 |
| Protocol | HTTPS only (TLS 1.2+) | HTTPS only (TLS 1.2+) |

Verify all three query operations return funcCode=OK with valid credentials:
1. **queryInvoiceData**: `/invoiceService/v3/queryInvoiceData`
2. **queryInvoiceDigest**: `/invoiceService/v3/queryInvoiceDigest`
3. **queryTransactionStatus**: `/invoiceService/v3/queryTransactionStatus`

---

## Authentication test cases

Authentication failures represent the most common integration issues. Each test case includes specific inputs, expected results, and diagnostic guidance.

### TC-AUTH-001: Valid credential authentication

**Objective**: Verify successful authentication with correct credentials

**Preconditions**: Valid technical user created in NAV portal with "Számlák lekérdezése" permission

**Test Data**:
```xml
<common:user>
  <common:login>VALID_TECH_USER</common:login>
  <common:passwordHash cryptoType="SHA-512">CORRECT_HASH</common:passwordHash>
  <common:taxNumber>12345678</common:taxNumber>
  <common:requestSignature cryptoType="SHA3-512">VALID_SIGNATURE</common:requestSignature>
</common:user>
```

**Expected Result**: Response with `<funcCode>OK</funcCode>`

**Validation Criteria**: No error codes in response; operation-specific data returned

---

### TC-AUTH-002: Invalid login name

**Objective**: Verify proper error handling for non-existent technical user

**Test Data**: Login = "NONEXISTENT_USER" (15 random characters)

**Expected Result**: 
```xml
<result>
  <funcCode>ERROR</funcCode>
  <errorCode>INVALID_SECURITY_USER</errorCode>
</result>
```

**Validation Criteria**: HTTP 200 with ERROR funcCode; verify no sensitive data leaked in error message

---

### TC-AUTH-003: Incorrect password hash

**Objective**: Test authentication failure with wrong password

**Test Variations**:
| Scenario | Password Hash Input | Expected Error |
|----------|-------------------|----------------|
| Wrong password | SHA-512("wrongpassword") | INVALID_SECURITY_USER |
| Lowercase hash | sha-512(password).toLowerCase() | INVALID_SECURITY_USER |
| Wrong algorithm | SHA-256(password) | INVALID_SECURITY_USER |
| Empty hash | "" | SCHEMA_VIOLATION |

**Validation Criteria**: All variations return INVALID_SECURITY_USER or SCHEMA_VIOLATION; no authentication bypass possible

---

### TC-AUTH-004: Invalid request signature calculation

**Objective**: Verify signature validation catches manipulation

**Test Variations**:
| Scenario | Signature Modification | Expected Error |
|----------|----------------------|----------------|
| Wrong signing key | Use incorrect signKey value | INVALID_REQUEST_SIGNATURE |
| Timestamp not masked | Use "2024-01-15T10:30:00Z" instead of "20240115103000" | INVALID_REQUEST_SIGNATURE |
| Missing request ID | Exclude requestId from hash input | INVALID_REQUEST_SIGNATURE |
| SHA-512 instead of SHA3-512 | Use wrong algorithm | INVALID_REQUEST_SIGNATURE |
| Lowercase result | signature.toLowerCase() | INVALID_REQUEST_SIGNATURE |

**Critical Note**: RequestIds from INVALID_REQUEST_SIGNATURE errors **cannot be reused**—generate new ID for retry

---

### TC-AUTH-005: Timestamp tolerance validation

**Objective**: Verify ±1 day timestamp tolerance enforcement

**Test Data Matrix**:
| Timestamp Offset | Expected Result |
|-----------------|-----------------|
| Current UTC time | OK |
| UTC +23 hours | OK |
| UTC -23 hours | OK |
| UTC +25 hours | INVALID_TIMESTAMP |
| UTC -25 hours | INVALID_TIMESTAMP |
| Local time (not UTC) | INVALID_TIMESTAMP |

**Timestamp Format**: `YYYY-MM-DDTHH:mm:ss.SSSZ` (ISO 8601 UTC)

---

### TC-AUTH-006: Tax number format validation

**Objective**: Test Hungarian tax number format requirements

**Valid Format**: 8 digits (e.g., "12345678")

**Test Variations**:
| Input | Expected Result |
|-------|----------------|
| "12345678" | OK |
| "1234567" (7 digits) | SCHEMA_VIOLATION |
| "123456789" (9 digits) | SCHEMA_VIOLATION |
| "1234567A" (contains letter) | SCHEMA_VIOLATION |
| "12345678-2-41" (with VAT code) | SCHEMA_VIOLATION |
| "" (empty) | SCHEMA_VIOLATION |

---

## Functional test cases for invoice queries

### queryInvoiceDigest test cases

This operation retrieves invoice summaries based on search criteria with **mandatory date range parameters**.

### TC-QID-001: Basic date range search (OUTBOUND)

**Request**:
```xml
<QueryInvoiceDigestRequest>
  <page>1</page>
  <invoiceDirection>OUTBOUND</invoiceDirection>
  <invoiceQueryParams>
    <mandatoryQueryParams>
      <invoiceIssueDate>
        <dateFrom>2024-01-01</dateFrom>
        <dateTo>2024-01-31</dateTo>
      </invoiceIssueDate>
    </mandatoryQueryParams>
  </invoiceQueryParams>
</QueryInvoiceDigestRequest>
```

**Expected Response Elements**:
- `currentPage`: 1
- `availablePage`: Total pages count
- `invoiceDigest`: Array of invoice summaries

**Validation Criteria**: All returned invoices have issueDate within specified range; supplier tax number matches authenticated user's tax number

---

### TC-QID-002: INBOUND direction query

**Objective**: Query invoices where authenticated taxpayer is the customer

**Key Difference**: For INBOUND queries, supplierTaxNumber becomes a filter parameter

**Expected Behavior**: Returns invoices issued TO the authenticated taxpayer, not BY them

**Validation Criteria**: All returned invoices have customerTaxNumber matching authenticated user; supplierTaxNumber varies

---

### TC-QID-003: Pagination handling

**Objective**: Verify correct pagination across large result sets

**Test Sequence**:
1. Query page 1, note `availablePage` value
2. Query each page from 1 to availablePage
3. Collect all invoiceNumbers
4. Verify no duplicates across pages
5. Verify total count matches sum of page results

**Edge Cases**:
| Scenario | page Parameter | Expected Result |
|----------|---------------|-----------------|
| Page 0 | 0 | SCHEMA_VIOLATION |
| Negative page | -1 | SCHEMA_VIOLATION |
| Beyond available | availablePage + 1 | Empty invoiceDigest array |
| Very large page | 999999 | Empty invoiceDigest array |

---

### TC-QID-004: Empty result handling

**Test Data**: Date range with no invoices (e.g., dateFrom="1990-01-01", dateTo="1990-01-02")

**Expected Response**:
```xml
<invoiceDigestResult>
  <currentPage>1</currentPage>
  <availablePage>0</availablePage>
</invoiceDigestResult>
```

**Validation Criteria**: funcCode=OK (not ERROR); empty result is valid response

---

### TC-QID-005: Additional query parameters

**Objective**: Test optional filter combinations

**Test Matrix**:
| Filter Parameter | Test Value | Validation |
|-----------------|------------|------------|
| taxNumber | "87654321" | Results filtered to specific partner |
| invoiceCategory | "NORMAL" | Only NORMAL invoices returned |
| paymentMethod | "TRANSFER" | Only transfer payments returned |
| invoiceAppearance | "ELECTRONIC" | Only e-invoices returned |
| currency | "EUR" | Only EUR invoices returned |
| source | "XML" | Only XML-submitted invoices |

---

### TC-QID-006: Relational query operators

**Objective**: Test comparison operators for date/amount fields

**Operators**: EQ (equal), GT (greater than), GTE (greater or equal), LT (less than), LTE (less or equal)

**Test Example (invoiceDelivery)**:
```xml
<relationalQueryParams>
  <invoiceDelivery>
    <queryOperator>GTE</queryOperator>
    <queryValue>2024-01-15</queryValue>
  </invoiceDelivery>
</relationalQueryParams>
```

**Validation Criteria**: All returned invoices satisfy the relational condition

---

### queryInvoiceData test cases

### TC-QDA-001: Retrieve complete invoice by number

**Request**:
```xml
<QueryInvoiceDataRequest>
  <invoiceNumberQuery>
    <invoiceNumber>INV-2024-001</invoiceNumber>
    <invoiceDirection>OUTBOUND</invoiceDirection>
  </invoiceNumberQuery>
</QueryInvoiceDataRequest>
```

**Expected Response**:
- `invoiceData`: BASE64-encoded invoice XML
- `auditData`: Processing metadata (insDate, transactionId, source)
- `compressedContentIndicator`: false (or true if originally compressed)

**Validation Criteria**: Decoded invoiceData validates against invoiceData.xsd; auditData.transactionId is non-empty

---

### TC-QDA-002: Non-existent invoice number

**Test Data**: invoiceNumber = "DOES_NOT_EXIST_12345"

**Expected Result**: funcCode=OK with empty/null invoiceDataResult

**Validation Criteria**: No ERROR returned; application handles null response gracefully

---

### TC-QDA-003: Batch invoice retrieval

**Objective**: Query specific invoice within a batch submission

**Request Parameters**:
- invoiceNumber: "BATCH-INV-001"
- invoiceDirection: "OUTBOUND"
- batchIndex: 3 (third invoice in batch)

**Validation Criteria**: Returns specific invoice from batch, not entire batch

---

### queryTransactionStatus test cases

### TC-QTS-001: Successful transaction status

**Request**:
```xml
<QueryTransactionStatusRequest>
  <transactionId>ABC123DEF456</transactionId>
  <returnOriginalRequest>false</returnOriginalRequest>
</QueryTransactionStatusRequest>
```

**Expected Response Processing Statuses**:
| Status | Meaning | Action Required |
|--------|---------|----------------|
| RECEIVED | Queued for processing | Poll again in 5-10 seconds |
| PROCESSING | Currently being processed | Poll again in 5-10 seconds |
| SAVED | Under business validation | Poll again |
| DONE | Successfully processed | No further action |
| ABORTED | Processing failed | Check validation messages |

---

### TC-QTS-002: Transaction status polling strategy

**Objective**: Verify robust polling implementation

**Recommended Algorithm**:
```
maxAttempts = 30
pollInterval = 5 seconds
timeout = 150 seconds

for attempt in 1..maxAttempts:
    status = queryTransactionStatus(transactionId)
    if status in [DONE, ABORTED]:
        return status
    sleep(pollInterval)
    
throw TimeoutException
```

**Validation Criteria**: Implementation handles all intermediate states; doesn't declare failure prematurely

---

### TC-QTS-003: Invalid transaction ID

**Test Data**: transactionId = "INVALID_TRANSACTION_ID"

**Expected Result**: funcCode=OK with empty processingResults

**Validation Criteria**: No ERROR; application handles missing transaction gracefully

---

## Error handling test cases

### NAV error codes comprehensive testing

### TC-ERR-001: Authentication errors

| Error Code | Trigger Condition | Test Method |
|------------|------------------|-------------|
| INVALID_SECURITY_USER | Wrong credentials | Use invalid login/password |
| INVALID_REQUEST_SIGNATURE | Wrong signature | Modify hash calculation |
| INVALID_TIMESTAMP | Time drift >24h | Set system clock offset |
| FORBIDDEN | Missing permission | Remove user permissions in portal |

---

### TC-ERR-002: Validation errors

| Error Code | Trigger Condition | Test Method |
|------------|------------------|-------------|
| SCHEMA_VIOLATION | Invalid XML structure | Remove required element |
| INVALID_REQUEST_VERSION | Wrong API version | Set requestVersion="2.0" |
| INVALID_HEADER_VERSION | Wrong header version | Set headerVersion="2.0" |
| DUPLICATE_REQUEST | Reused requestId | Submit same requestId twice |

---

### TC-ERR-003: Technical errors

| Error Code | Trigger Condition | Recovery Strategy |
|------------|------------------|-------------------|
| MAINTENANCE | System maintenance | Retry after maintenance window |
| SERVICE_UNAVAILABLE | Service down | Exponential backoff retry |
| INTERNAL_ERROR | Server error | Log and retry with new requestId |

**Retry Implementation**:
```
baseDelay = 1 second
maxDelay = 60 seconds
maxRetries = 5

for retry in 1..maxRetries:
    delay = min(baseDelay * (2 ^ retry), maxDelay)
    sleep(delay)
    result = submitRequest(newRequestId)
    if result.funcCode == "OK":
        return result
```

---

### TC-ERR-004: Network timeout handling

**Test Scenarios**:
| Scenario | Simulation Method | Expected Behavior |
|----------|------------------|-------------------|
| Connection timeout | Block outbound traffic | Retry with backoff |
| Read timeout (>60s) | Slow response simulation | Transaction may be lost |
| SSL handshake failure | Invalid certificates | Fail fast, log error |

**Critical**: For read timeouts during manageInvoice, use `queryTransactionList` to find orphaned transactions

---

### TC-ERR-005: Rate limiting scenarios

**NAV Rate Limits**:
- **1 request per second** per IP address
- Excess requests incur **+4000ms delay** per request
- Requests waiting **>60 seconds** are terminated

**Test Approach**:
1. Send 5 requests simultaneously
2. Measure response times
3. Verify delays accumulate (request 5 should take ~16 seconds)
4. Send burst of 20 requests
5. Verify some requests timeout after 60 seconds

**Validation Criteria**: Application respects rate limits; implements proper backoff

---

### TC-ERR-006: Malformed XML response handling

**Objective**: Verify resilience to unexpected responses

**Test Scenarios**:
| Scenario | Simulation Method | Expected Behavior |
|----------|------------------|-------------------|
| Empty response body | Mock empty 200 response | Parse error, retry |
| Truncated XML | Mock incomplete response | Parse error, retry |
| Wrong content type | Return JSON instead | Content type error |
| HTML error page | Mock 500 with HTML | Detect non-XML, log error |

---

## Security test cases

### TC-SEC-001: TLS enforcement validation

**Objective**: Verify TLS 1.2 minimum requirement

**Test Method**:
```bash
# Test TLS 1.2 support
openssl s_client -connect api.onlineszamla.nav.gov.hu:443 -tls1_2

# Verify TLS 1.1 rejected
openssl s_client -connect api.onlineszamla.nav.gov.hu:443 -tls1_1
# Should fail: no protocols available
```

**Validation Criteria**: TLS 1.2 and 1.3 connections succeed; TLS 1.0/1.1 connections fail

---

### TC-SEC-002: Credential storage validation

**Audit Checklist**:
| Requirement | Verification Method | Pass Criteria |
|-------------|--------------------| --------------|
| Passwords not in plaintext | Code review, config audit | Encrypted or environment variables |
| Signing keys protected | Access control audit | Limited file permissions |
| No credentials in logs | Log file inspection | Zero credential occurrences |
| No credentials in errors | Exception handling review | Sanitized error messages |
| Secure config storage | Infrastructure audit | Encrypted secrets manager |

---

### TC-SEC-003: Signature tampering detection

**Objective**: Verify requests cannot be modified after signing

**Test Sequence**:
1. Generate valid signed request
2. Modify any field (e.g., add 1 to page number)
3. Submit modified request
4. Verify INVALID_REQUEST_SIGNATURE error

**Validation Criteria**: Any post-signature modification results in rejection

---

### TC-SEC-004: Request ID replay prevention

**Objective**: Verify requestId cannot be reused

**Test Sequence**:
1. Submit valid request, capture requestId
2. Wait 1 minute
3. Submit new request with same requestId
4. Verify DUPLICATE_REQUEST error

**Note**: RequestId uniqueness enforced within ±1 day timestamp window

---

## Performance test cases

### TC-PERF-001: Rate limiting compliance

**Objective**: Verify application respects NAV rate limits

**Test Configuration**:
- Concurrent users: 1
- Requests per second: 1 (maximum allowed)
- Duration: 60 seconds
- Expected successful requests: 60

**Validation Criteria**: Zero rate limit violations; all requests complete within 5 seconds

---

### TC-PERF-002: Concurrent request handling

**Objective**: Test application behavior under concurrent load

**Scenario 1 - Single IP**: Multiple threads sharing IP
- Expected: Requests queue with 4-second penalties
- Validation: Total time = n * 4 seconds (approximate)

**Scenario 2 - Multiple IPs**: Load balanced across IPs
- Expected: Each IP gets 1 req/sec limit independently
- Validation: Throughput scales with IP count

---

### TC-PERF-003: Large dataset pagination performance

**Objective**: Measure performance retrieving large result sets

**Test Data**: Query returning 1000+ invoices (50+ pages)

**Metrics to Capture**:
| Metric | Target | Maximum |
|--------|--------|---------|
| Time per page | <500ms | 2000ms |
| Total retrieval (1000 invoices) | <60s | 180s |
| Memory usage | Stable | No memory leak |

---

### TC-PERF-004: Large invoice data retrieval

**Objective**: Test handling of maximum-size invoices

**Test Data**: Invoice with maximum allowed content:
- 15 MB uncompressed invoice data
- 100 line items
- All optional fields populated

**Validation Criteria**: Successful retrieval; proper decompression if compressed; no timeout

---

## Integration test scenarios

### TC-INT-001: End-to-end invoice submission workflow

**Workflow Steps**:
```
1. tokenExchange → Obtain session token
2. manageInvoice(CREATE) → Submit invoice, get transactionId
3. queryTransactionStatus → Poll until DONE/ABORTED
4. queryInvoiceData → Verify invoice stored correctly
5. queryInvoiceDigest → Verify invoice appears in search
```

**Validation Points**:
| Step | Success Criteria |
|------|-----------------|
| Token exchange | Valid token returned |
| Invoice submission | TransactionId returned |
| Status polling | Final status DONE |
| Data retrieval | Invoice matches submitted data |
| Digest search | Invoice found in date range query |

---

### TC-INT-002: Invoice modification workflow

**Workflow Steps**:
```
1. Create original invoice (invoiceNumber: "INV-001")
2. Verify original accepted (status: DONE)
3. Submit MODIFY invoice referencing "INV-001"
4. Verify modification accepted
5. Query invoice chain (queryInvoiceChainDigest)
6. Verify chain shows both invoices
```

**Critical Validation**: modificationIndex increments correctly; original invoice shows modification reference

---

### TC-INT-003: Invoice cancellation (STORNO) workflow

**Workflow**:
```
1. Create original invoice
2. Verify acceptance
3. Submit STORNO invoice with same invoiceNumber
4. Verify cancellation accepted
5. Query original invoice
6. Verify cancellation flag/status reflected
```

---

## September 2025 regression test cases

The following validations transition from **WARN to ERROR** on September 15, 2025. Test these in NAV test environment starting September 1, 2025.

### TC-REG-001: Performance period date validation (Code 330)

**New Rule**: Performance period closing date cannot be earlier than opening date

**Test Data**:
```xml
<lineDeliveryDate>2024-01-15</lineDeliveryDate>
<lineDeliveryDateTo>2024-01-10</lineDeliveryDateTo> <!-- ERROR: end before start -->
```

**Expected Result (after Sept 15)**: ERROR blocking submission

**Fix**: Ensure deliveryDateTo >= deliveryDate

---

### TC-REG-002: Invoice modification number validation (Code 560)

**New Rule**: Modification invoice number cannot be identical to original

**Test Data**:
```xml
<invoiceNumber>INV-2024-001</invoiceNumber>
<modificationReference>
  <originalInvoiceNumber>INV-2024-001</originalInvoiceNumber> <!-- ERROR: same number -->
</modificationReference>
```

**Fix**: Generate distinct modification invoice numbers

---

### TC-REG-003: Domestic reverse charge buyer validation (Code 596)

**New Rule**: Domestic reverse charge requires buyer to be domestic VAT taxpayer

**Test Data**:
```xml
<vatExemption>
  <vatExemptionCase>AAM</vatExemptionCase> <!-- Reverse charge -->
</vatExemption>
<customerTaxNumber>
  <taxpayerId>12345678</taxpayerId>
  <vatCode>1</vatCode> <!-- Non-domestic indicator -->
</customerTaxNumber>
```

**Fix**: Verify buyer VAT status before applying reverse charge

---

### TC-REG-004: Exchange rate validation (Codes 1300, 1310)

**Code 1300**: Exchange rate doesn't match HUF/foreign currency ratio

**Code 1310**: Extreme exchange rate values (unrealistic rates)

**Test Data**:
```xml
<invoiceSummary>
  <invoiceNetAmountHUF>100000</invoiceNetAmountHUF>
  <invoiceNetAmount>1000</invoiceNetAmount>
  <currencyCode>EUR</currencyCode>
  <exchangeRate>0.01</exchangeRate> <!-- ERROR: implies 1 EUR = 0.01 HUF -->
</invoiceSummary>
```

**Fix**: Validate exchange rates against published MNB rates (±reasonable tolerance)

---

### TC-REG-005: VAT exemption data presence (Codes 591, 593, 701)

**New Rules**:
- VAT data cannot be present when invoice marked as VAT exempt (591)
- VAT data cannot be present when marked "outside scope of VAT Act" (593, 701)

**Test Data**:
```xml
<vatExemption>
  <vatExemptionCase>TAM</vatExemptionCase> <!-- Exempt -->
</vatExemption>
<vatRateNet>10000</vatRateNet>
<vatRateAmount>2700</vatRateAmount> <!-- ERROR: VAT data with exemption -->
```

**Fix**: Clear VAT amount fields when exemption applied

---

### TC-REG-006: Collective invoice performance date (Code 620)

**New Rule**: Performance date required for each collective invoice item

**Test Data**:
```xml
<invoiceCategory>AGGREGATE</invoiceCategory>
<invoiceLine>
  <lineNumber>1</lineNumber>
  <!-- Missing lineDeliveryDate --> <!-- ERROR after Sept 15 -->
</invoiceLine>
```

**Fix**: Always populate lineDeliveryDate for aggregate invoices

---

### TC-REG-007: Unit of measure OWN validation (Code 434)

**New Rule**: When unitOfMeasure is "OWN", unitOfMeasureOwn element required

**Test Data**:
```xml
<unitOfMeasure>OWN</unitOfMeasure>
<!-- Missing unitOfMeasureOwn --> <!-- ERROR -->
```

**Fix**: Always provide unitOfMeasureOwn when using custom unit

---

### TC-REG-008: Already cancelled invoice modification (Code 1140)

**New Rule**: Cannot modify an invoice that has already been cancelled

**Test Sequence**:
1. Create invoice "INV-001"
2. Cancel invoice "INV-001" with STORNO
3. Attempt MODIFY on "INV-001"
4. Expected: ERROR (was WARN)

---

### Complete September 2025 regression test matrix

| Code | Validation Rule | Test Priority |
|------|----------------|---------------|
| 82 | Invalid buyer VAT group tax number | HIGH |
| 91 | Tax number VAT group reporting issue | HIGH |
| 330 | Performance period end before start | HIGH |
| 434 | Missing unitOfMeasureOwn for OWN | MEDIUM |
| 560 | Modification number = original number | HIGH |
| 581-584 | Incorrect VAT marking for tax codes | MEDIUM |
| 591 | VAT data with exemption | HIGH |
| 593 | VAT data with out-of-scope | HIGH |
| 596 | Reverse charge non-domestic buyer | HIGH |
| 620 | Missing performance date in aggregate | MEDIUM |
| 701 | VAT summary with out-of-scope | MEDIUM |
| 1140 | Modify cancelled invoice | HIGH |
| 1150 | Unrealistic modification sequence | MEDIUM |
| 1300 | Exchange rate mismatch | HIGH |
| 1310 | Extreme exchange rate | HIGH |

---

## Test data requirements

### Required test invoices

**Minimum Test Invoice Set**:
1. **Simple B2B invoice**: Single item, HUF, domestic transaction
2. **Multi-line invoice**: 10+ line items with different VAT rates
3. **Foreign currency invoice**: EUR with exchange rate
4. **Reverse charge invoice**: Domestic reverse charge scenario
5. **VAT exempt invoice**: Export or exempt transaction
6. **Aggregate invoice**: Multiple performance periods
7. **Modification invoice**: Correcting previous invoice
8. **Storno invoice**: Cancellation document
9. **Large invoice**: 100 line items, maximum data
10. **Edge case invoice**: All optional fields populated

### Test tax numbers for NAV test environment

| Purpose | Tax Number | Note |
|---------|-----------|------|
| Your company | Register in test portal | Create technical user |
| Domestic partner | Any 8-digit format | e.g., "12345678" |
| EU partner | Any valid EU VAT format | e.g., "DE123456789" |
| Non-EU partner | Use third-country code | Country code required |

### Sample request templates

**queryInvoiceDigest Template**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<QueryInvoiceDigestRequest xmlns="http://schemas.nav.gov.hu/OSA/3.0/api"
    xmlns:common="http://schemas.nav.gov.hu/NTCA/1.0/common">
  <common:header>
    <common:requestId>TEST_{UUID}</common:requestId>
    <common:timestamp>{ISO8601_UTC}</common:timestamp>
    <common:requestVersion>3.0</common:requestVersion>
    <common:headerVersion>1.0</common:headerVersion>
  </common:header>
  <common:user>
    <common:login>{TECH_USER}</common:login>
    <common:passwordHash cryptoType="SHA-512">{SHA512_HASH}</common:passwordHash>
    <common:taxNumber>{TAX_NUMBER}</common:taxNumber>
    <common:requestSignature cryptoType="SHA3-512">{SIGNATURE}</common:requestSignature>
  </common:user>
  <software>
    <softwareId>{SOFTWARE_ID}</softwareId>
    <softwareName>Test Software</softwareName>
    <softwareOperation>ONLINE_SERVICE</softwareOperation>
    <softwareMainVersion>1.0</softwareMainVersion>
    <softwareDevName>Test Developer</softwareDevName>
    <softwareDevContact>dev@test.com</softwareDevContact>
  </software>
  <page>1</page>
  <invoiceDirection>OUTBOUND</invoiceDirection>
  <invoiceQueryParams>
    <mandatoryQueryParams>
      <invoiceIssueDate>
        <dateFrom>2024-01-01</dateFrom>
        <dateTo>2024-12-31</dateTo>
      </invoiceIssueDate>
    </mandatoryQueryParams>
  </invoiceQueryParams>
</QueryInvoiceDigestRequest>
```

---

## Automated testing approaches

### CI/CD pipeline integration

**GitHub Actions workflow**:
```yaml
name: NAV API Integration Tests

on:
  push:
    branches: [main, develop]
  schedule:
    - cron: '0 6 * * *'  # Daily 6 AM

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: XSD Schema Validation
        run: |
          find tests/fixtures -name "*.xml" -exec xmllint --schema schemas/invoiceApi.xsd {} --noout \;
      
      - name: Unit Tests (Hash Calculation)
        run: npm test -- --grep "hash"
        
      - name: Integration Tests (Test Environment)
        run: npm test -- --grep "integration"
        env:
          NAV_API_URL: ${{ secrets.NAV_TEST_API_URL }}
          NAV_LOGIN: ${{ secrets.NAV_TEST_LOGIN }}
          NAV_SIGN_KEY: ${{ secrets.NAV_TEST_SIGN_KEY }}
```

### Recommended testing tools

| Tool | Purpose | Integration |
|------|---------|-------------|
| **SoapUI** | XML/API testing, assertions | Jenkins, CLI runner |
| **Postman/Newman** | API testing, collections | CLI, GitHub Actions |
| **xmllint** | XSD validation | Any CI system |
| **JMeter** | Performance testing | Jenkins plugin |
| **Custom scripts** | Hash verification | Any language |

### Continuous validation strategy

```
Daily Tests:
├── Authentication health check
├── Basic query operation verification
└── XSD schema compliance scan

Weekly Tests:
├── Full regression suite
├── Performance baseline comparison
└── Error handling validation

Pre-Release Tests:
├── Complete integration workflow
├── September 2025 regression suite
└── Security audit checklist
```

---

## Production readiness checklist

### Pre-deployment gates

| Gate | Requirement | Evidence |
|------|-------------|----------|
| **Authentication** | All auth tests pass | Test report |
| **Query Operations** | All 3 operations functional | Integration test results |
| **Error Handling** | All error codes handled | Code coverage report |
| **Security** | TLS 1.2+, credentials secured | Security audit |
| **Performance** | Rate limits respected | Load test results |
| **Sept 2025 Compliance** | All 15 new validations pass | Regression test report |

### Rollback procedures

**Immediate Rollback Triggers**:
- Authentication failures in production
- SCHEMA_VIOLATION errors on previously working invoices
- Rate limit violations causing timeouts
- Data corruption indicators

**Rollback Steps**:
1. Switch to previous version deployment
2. Verify authentication works
3. Test basic query operation
4. Monitor error rates for 30 minutes
5. Investigate root cause before retry

### Monitoring requirements

**Critical Metrics**:
| Metric | Alert Threshold | Action |
|--------|----------------|--------|
| Error rate | >5% of requests | Page on-call |
| Response time | >2000ms average | Investigate |
| Authentication failures | >3 consecutive | Credential check |
| Rate limit delays | >10 seconds | Reduce throughput |

**Log Requirements**:
- All API requests/responses (sanitized)
- Transaction IDs for all submissions
- Processing status poll results
- Error codes with timestamps

### Error recovery strategies

**Lost Transaction Recovery**:
```
1. Query queryTransactionList for time period
2. Identify missing transactionIds
3. Match against local submission records
4. Resubmit only confirmed missing invoices
5. Verify no duplicates created
```

**Partial Submission Recovery**:
```
If batch submission fails mid-way:
1. Query status of each invoice index
2. Identify which invoices succeeded
3. Resubmit only failed invoices
4. Use different batch/requestId
```

---

## Conclusion

This testing framework addresses the complete lifecycle of NAV Online Számla API integration, from initial authentication validation through production monitoring. **The September 2025 changes represent the most significant validation update in recent years**—organizations should prioritize regression testing against the 15 new blocking errors before the September 15, 2025 deadline.

Key implementation priorities:
1. Establish automated daily authentication health checks
2. Integrate XSD validation into build pipeline before any deployment
3. Build comprehensive polling logic for queryTransactionStatus with proper timeout handling
4. Implement the complete September 2025 regression suite by September 1, 2025
5. Configure monitoring for error codes 1300 and 1310 (exchange rate)—these catch many existing implementations

For ongoing compliance, monitor the NAV GitHub repository discussions at `github.com/nav-gov-hu/Online-Invoice/discussions` for advance notice of future validation changes.