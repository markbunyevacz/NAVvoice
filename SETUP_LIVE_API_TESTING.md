# 🚀 Setup Guide: Live NAV API Testing

## Step-by-Step Instructions

This guide walks you through executing the **19 live NAV API tests** required by the Comprehensive Testing Framework.

---

## 📋 Prerequisites Checklist

Before starting, you need:
- [ ] Internet connection to NAV servers
- [ ] Ügyfélkapu+ account (Hungarian e-government login)
- [ ] DÁP mobile app or authenticator for 2FA
- [ ] 30-60 minutes for registration

---

## 🔐 Step 1: NAV Test Portal Registration

### 1.1 Navigate to NAV Test Portal
```
URL: https://onlineszamla-test.nav.gov.hu/
```

### 1.2 Login with Ügyfélkapu+
- Click "Belépés" (Login)
- Use your Ügyfélkapu+ credentials
- Complete 2FA authentication via DÁP app

### 1.3 Register Company
- Complete taxpayer registration form
- Enter company contact information
- Save registration

### 1.4 Create Technical User

**Navigation**: 
- Menu: "Felhasználók" (Users)
- Click: "Technikai felhasználó létrehozása" (Create Technical User)

**Configuration**:
- **Name**: "API Test User" (or your choice)
- **Permission**: ✅ Select **"Számlák lekérdezése"** (Query Invoices)
- **Optional**: Add "Számlák feltöltése" (Upload Invoices) for write tests
- Click "Mentés" (Save)

### 1.5 Generate Keys

**After saving user**:
- Click "Kulcsgenerálás" (Generate Keys)
- **IMPORTANT**: Save these 4 values immediately:

```
Login: _______________ (15 characters, auto-generated)
Password: _______________ (you define, save securely)
XML Aláírókulcs (Signature Key): _______________ (32 characters)
XML Cserekulcs (Exchange Key): _______________ (32 characters)
```

⚠️ **WARNING**: Password cannot be recovered - save it now!

---

## 💾 Step 2: Configure Environment Variables

### Windows PowerShell

Open PowerShell and run:

```powershell
# Set NAV test credentials
$env:NAV_TEST_LOGIN="YOUR_15_CHAR_LOGIN"
$env:NAV_TEST_PASSWORD="YOUR_PASSWORD"
$env:NAV_TEST_SIGNATURE_KEY="YOUR_32_CHAR_SIGNATURE_KEY"
$env:NAV_TEST_REPLACEMENT_KEY="YOUR_32_CHAR_EXCHANGE_KEY"
$env:NAV_TEST_TAX_NUMBER="YOUR_8_DIGIT_TAX_NUMBER"
$env:NAV_TEST_SOFTWARE_ID="HU12345678-TEST01"

# Verify they're set
echo $env:NAV_TEST_LOGIN
```

### Linux/Mac Bash

```bash
export NAV_TEST_LOGIN="YOUR_15_CHAR_LOGIN"
export NAV_TEST_PASSWORD="YOUR_PASSWORD"
export NAV_TEST_SIGNATURE_KEY="YOUR_32_CHAR_SIGNATURE_KEY"
export NAV_TEST_REPLACEMENT_KEY="YOUR_32_CHAR_EXCHANGE_KEY"
export NAV_TEST_TAX_NUMBER="YOUR_8_DIGIT_TAX_NUMBER"
export NAV_TEST_SOFTWARE_ID="HU12345678-TEST01"

# Verify
echo $NAV_TEST_LOGIN
```

### Permanent Configuration (Optional)

**Windows**: Add to PowerShell profile
```powershell
notepad $PROFILE
# Add the $env:NAV_TEST_* lines
```

**Linux/Mac**: Add to ~/.bashrc or ~/.zshrc
```bash
# Add the export NAV_TEST_* lines
```

---

## 🧪 Step 3: Execute Live API Tests

### 3.1 Navigate to Project Directory

```powershell
cd C:\Users\Admin\.cursor\NAVvoice
```

### 3.2 Run Live API Tests

```bash
# Execute all 19 live API tests
python -m pytest test_nav_live_api.py -v -s

# Or run with more detailed output
python -m pytest test_nav_live_api.py -v -s --tb=short
```

### 3.3 Expected Output

**If credentials are correct**:
```
test_nav_live_api.py::TestPreDeploymentValidation::test_timestamp_utc_submission PASSED
test_nav_live_api.py::TestPreDeploymentValidation::test_technical_user_credentials PASSED
✓ Token exchange successful: ...
test_nav_live_api.py::TestPreDeploymentValidation::test_software_registration_id PASSED
...
============================= 19 passed in XX.XXs ==============================
```

**If credentials are missing**:
```
19 skipped (Missing environment variables: NAV_TEST_LOGIN, ...)
```

**If credentials are wrong**:
```
FAILED ... NavApiError: INVALID_SECURITY_USER
```

---

## 🔍 Step 4: Interpret Results

### ✅ All 19 Tests Pass

**Meaning**: 
- ✅ NAV accepts your credentials
- ✅ NAV accepts your XML structure
- ✅ NAV accepts your signatures (SHA3-512)
- ✅ NAV token exchange works
- ✅ NAV error responses match specification
- ✅ NAV rate limiting verified

**Status**: ✅ **PRODUCTION APPROVED**

**Next**: Deploy to production with confidence

### ❌ Tests Fail

**Common Failures**:

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| INVALID_SECURITY_USER | Wrong login/password | Check credentials |
| INVALID_REQUEST_SIGNATURE | Wrong signature key or SHA algorithm | Verify signature_key value |
| SCHEMA_VIOLATION | XML structure wrong | Check namespace URIs |
| CONNECTION_ERROR | Network/firewall | Check internet connection |
| MISSING_TOKEN | Wrong exchange key | Verify replacement_key value |

**Action**: 
1. Review error message
2. Fix identified issue
3. Re-run tests
4. Repeat until all pass

---

## 📊 Test Coverage After Live Tests

### Before Live Tests (Current)
```
Unit Tests: 70 passing ✅
Live API Tests: 0 executed ❌
Framework Compliance: 0%
Production Ready: NO
```

### After Live Tests (Target)
```
Unit Tests: 70 passing ✅
Live API Tests: 19 passing ✅
Framework Compliance: 100% ✅
Production Ready: YES ✅
```

---

## 🎯 What Each Live Test Verifies

### Pre-deployment Tests (3 tests)
- **test_timestamp_utc_submission**: NAV accepts our UTC timestamps
- **test_technical_user_credentials**: Real tokenExchange succeeds
- **test_software_registration_id**: NAV accepts our software ID

### Endpoint Connectivity (3 tests)
- **test_query_invoice_data_endpoint**: queryInvoiceData works
- **test_query_invoice_digest_endpoint**: queryInvoiceDigest works
- **test_query_transaction_status_endpoint**: queryTransactionStatus works

### Authentication (3 tests)
- **test_tc_auth_001_valid_credentials_live**: Valid auth succeeds
- **test_tc_auth_002_invalid_login_live**: Wrong login returns INVALID_SECURITY_USER
- **test_tc_auth_003_incorrect_password_live**: Wrong password returns error

### Query Operations (6 tests)
- **test_tc_qid_001_basic_date_range_live**: Date range query works
- **test_tc_qid_002_inbound_direction_live**: INBOUND direction correct
- **test_tc_qid_004_empty_result_live**: Empty results handled
- **test_tc_qda_001_retrieve_invoice_live**: Full invoice retrieval
- **test_tc_qid_005_additional_params_live**: Filter parameters work
- **test_tc_qid_003_pagination_live**: Pagination works

### Error Handling (2 tests)
- **test_tc_err_001_authentication_error_live**: NAV error codes verified
- **test_tc_err_005_rate_limiting_live**: NAV rate limiting measured

### Integration (1 test)
- **test_tc_int_001_end_to_end_live**: Full submission workflow (requires write permission)

---

## ⏱️ Estimated Timeline

| Task | Time | Status |
|------|------|--------|
| NAV portal registration | 30-60 min | ⏳ Your action |
| Set environment variables | 1 min | ⏳ Your action |
| Run live tests | 2-5 min | ⏳ Waiting |
| Fix issues (if any) | 0-60 min | ⏳ TBD |
| **Total** | **30-120 min** | ⏳ **Waiting on you** |

---

## 🚦 Quick Commands Reference

```bash
# After setting environment variables:

# Check variables are set
echo $env:NAV_TEST_LOGIN  # PowerShell
echo $NAV_TEST_LOGIN      # Bash

# Run live tests
pytest test_nav_live_api.py -v -s

# Run with HTML report
pytest test_nav_live_api.py -v --html=live_api_report.html

# Run specific test
pytest test_nav_live_api.py::TestAuthenticationLive::test_tc_auth_001_valid_credentials_live -v -s
```

---

## 📞 Support

### If Tests Are Skipped
**Problem**: Missing environment variables  
**Solution**: Set all NAV_TEST_* variables from Step 2

### If Tests Fail with Auth Errors
**Problem**: Wrong credentials  
**Solution**: Verify credentials from NAV portal match environment variables exactly

### If Tests Fail with Network Errors
**Problem**: Can't reach NAV servers  
**Solution**: Check internet, firewall, proxy settings

### If You Need Help
**Reference**: 
- `Complete Technical Guide...md` - API specification
- `Comprehensive Testing Framework...md` - Test requirements
- NAV Support: https://onlineszamla.nav.gov.hu/dokumentaciok

---

## ✅ Success Criteria

After executing live tests, you should have:

```
============================= test session starts =============================
test_nav_live_api.py::TestPreDeploymentValidation::test_timestamp_utc_submission PASSED
test_nav_live_api.py::TestPreDeploymentValidation::test_technical_user_credentials PASSED
✓ Token exchange successful: ...
test_nav_live_api.py::TestPreDeploymentValidation::test_software_registration_id PASSED
...
============================= 19 passed in XX.XXs ==============================
```

**This proves**: 
- ✅ NAV accepts your implementation
- ✅ Framework requirements met
- ✅ Production deployment approved

---

**Current Status**: ⏸️ Waiting for NAV credentials  
**File Ready**: test_nav_live_api.py  
**Action Required**: Complete Steps 1-3 above  
**ETA to Production**: 2-4 hours

