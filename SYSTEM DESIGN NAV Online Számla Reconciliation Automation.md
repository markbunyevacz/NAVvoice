## Page 1

SYSTEM DESIGN: NAV Online Számla Reconciliation Automation
1. PROCESS IDENTIFICATION
Process Name: Automated Missing Invoice Reconciliation (NAV Online Számla vs. Received PDF)
Business Problem: Hungarian SMEs receive invoice data from NAV Online Számla API (XML format) but often
don't receive the actual PDF invoices from vendors. This creates:
• VAT reclaim risks (ÁFA-visszaigénylés kockázat)
• Potential penalties up to 1M HUF per invoice (2025 September regulations)
• eÁFA declaration mismatches
• Lost accounting documentation
2. SYSTEM ARCHITECTURE
Tools Stack:
• Email: Gmail (with dedicated email address: szamla-bot@company.com)
• Spreadsheet: Google Sheets (3 sheets in one workbook)
• Automation: Make.com (preferred for complex logic) or Zapier
Data Storage Structure:
Google Sheets Workbook: "NAV-Invoice-Reconciliation"
├── Sheet 1: "NAV_Data" (Master list from NAV API)
├── Sheet 2: "Received_PDFs" (Tracked incoming invoices)
├── Sheet 3: "Missing_Invoices" (Action queue)
└── Sheet 4: "Audit_Log" (Process history)
3. TRIGGERS
A. Time-Based Trigger (Daily Reconciliation)
Schedule: Daily at 7:00 AM CET (before business hours)
Trigger Configuration (Make.com):
Module: Schedule
- Frequency: Every day
- Time: 07:00 CET
- Timezone: Europe/Budapest
Purpose: Compare NAV_Data against Received_PDFs to identify missing invoices
B. Event-Based Trigger (Email Ingestion)
Trigger Configuration (Make.com):

## Page 2

Module: Gmail > Watch Emails
- Mailbox: szamla-bot@company.com
- Folder: INBOX
- Filter: has:attachment filename:pdf
- Labels: "Számla Feldolgozás"
Purpose: Automatically capture and process incoming vendor invoices sent via email
4. DATA TO BE CAPTURED
NAV_Data Sheet Columns:
Column Field Name (Hungarian) Field Name (English) Data Type Source
A Számlaszám Invoice Number Text NAV API invoiceNumber
B Szállító Neve Vendor Name Text NAV API supplierName
C Szállító Adószám Vendor Tax ID Text NAV API supplierTaxNumber
D Nettó Összeg Net Amount Number NAV API invoiceNetAmount
E ÁFA Összeg VAT Amount Number NAV API invoiceVatAmount
F Bruttó Összeg Gross Amount Number NAV API invoiceGrossAmount
G Teljesítés Dátuma Performance Date Date NAV API completionDate
H Számla Kelte Invoice Date Date NAV API invoiceIssueDate
I Pénznem Currency Text NAV API invoiceCurrency
J NAV Lekérés Időpontja NAV Fetch Timestamp DateTime System generated
K Státusz Processing Status Dropdown System managed
Status Values (Column K):
• 🟡 Folyamatban (In Progress)
• 🟢 PDF Megérkezett (PDF Received)
• 🔴 Hiányzik - Email Elküldve (Missing - Email Sent)
• ⚪ Manuális Ellenőrzés (Manual Review)
Received_PDFs Sheet Columns:
Column Field Name Data Type Source
A Számlaszám Text Extracted from PDF/Email
B Szállító Text Email sender or PDF OCR
C Összeg Number PDF OCR or manual
D Fogadás Dátuma DateTime Email received timestamp
E Gmail Message ID Text Email message ID for reference

## Page 3

F Drive File Link URL Google Drive PDF URL
G Feldolgozó Text "Automation" or user name
H Megjegyzés Text Notes/Errors
Missing_Invoices Sheet Columns:
Column Field Name Purpose
A Számlaszám Reference
B Szállító Neve Contact target
C Szállító Email Contact address
D Összeg For email context
E Hiány Észlelve Timestamp
F Email Elküldve Timestamp
G Ismétlési Számláló Reminder count (max 3)
H Kézi Beavatkozás Kért Boolean flag
5. RULES AND BRANCHES
BRANCH A: Ingestion Branch (Event-Based)
Trigger: Email arrives with PDF attachment
Flow:
1. Gmail Watch New Email
↓
2. Filter: [IF attachment contains ".pdf"]
↓
3. Extract Email Metadata
- Sender email
- Subject line
- Received timestamp
- Message ID
↓
4. Download PDF Attachment
↓
5. Upload to Google Drive
- Folder: "/NAV_Invoices/Received_PDFs/YYYY-MM/"
- Naming: "{InvoiceNumber}_{VendorName}_{Date}.pdf"
↓
6. OCR/Parse PDF (using Google Cloud Vision or Make's PDF parser)
- Extract: Invoice Number, Vendor Name, Amount
↓
7. Add Row to "Received_PDFs" Sheet
- Columns: A-H as defined above
↓
8. Mark Gmail Email with Label: "✅ Feldolgozva"

## Page 4

↓
9. [IF Invoice Number found in NAV_Data]
→ Update NAV_Data Status: "🟢 PDF Megérkezett"
→ Remove from Missing_Invoices (if present)
↓
10. Send Confirmation Email (optional)
- To: sender
- Subject: "Számlát fogadtuk: {InvoiceNumber}"
Error Handling within Branch:
• No PDF found: Label email "⚠️ Nincs PDF", add to Audit_Log
• OCR fails: Mark as "⚪ Manuális Ellenőrzés", notify admin
• Duplicate Invoice Number: Check Drive, flag in Audit_Log
BRANCH B: Reconciliation Branch (Time-Based)
Trigger: Daily at 7:00 AM
Flow:
1. Fetch All Rows from "NAV_Data" Sheet
- Filter: Status != "🟢 PDF Megérkezett"
↓
2. Fetch All Rows from "Received_PDFs" Sheet
↓
3. For Each NAV Invoice:
↓
3a. Search Matching Invoice Number in Received_PDFs
↓
[IF MATCH FOUND]
→ Update NAV_Data Status: "🟢 PDF Megérkezett"
→ SKIP to next invoice
↓
[IF NO MATCH]
→ Proceed to Step 4
↓
4. Check Missing_Invoices Sheet
↓
[IF Invoice already in Missing_Invoices]
→ Check "Ismétlési Számláló" value
↓
[IF counter < 3 AND more than 3 days since last email]
→ Increment counter
→ Proceed to Action Branch (Step 5)
↓
[IF counter >= 3]
→ Set "Kézi Beavatkozás Kért" = TRUE
→ Send notification to human (Accounting Manager)
→ STOP automation for this invoice
↓
[IF Invoice NOT in Missing_Invoices]
→ Add new row to Missing_Invoices
→ Set counter = 0
→ Proceed to Action Branch (Step 5)

## Page 5

BRANCH C: Action Logic (Missing Invoice Handling)
Triggered by: Branch B identifies missing invoice
Flow:
5. Lookup Vendor Contact Info
↓
5a. Search "Szállító Adószám" in internal CRM/Vendor Sheet
→ Get: Vendor Email, Contact Person
↓
[IF Vendor Email exists]
→ Proceed to Step 6
↓
[IF NO Email]
→ Set Status: "⚪ Manuális Ellenőrzés - Nincs Email"
→ Notify human
→ STOP
↓
6. Generate Personalized Email (using AI/Template)
↓
Template:
---
Tárgy: Hiányzó számla pótlása - {Számlaszám}
Kedves {Szállító Neve}!
A Nemzeti Adó- és Vámhivatal Online Számla rendszerében
látjuk az alábbi számláját:
- Számlaszám: {Számlaszám}
- Összeg: {Bruttó Összeg} HUF
- Teljesítés dátuma: {Teljesítés Dátuma}
Sajnos a PDF formátumú bizonylat nem érkezett meg részünkre.
Kérjük, küldje el a számlát válaszüzenetben, vagy töltse fel ide:
[Upload Link to Google Form]
Köszönjük együttműködését!
Üdvözlettel,
{Cég Neve} Pénzügyi Osztály
(Ez egy automatikus üzenet)
---
↓
7. Send Email via Gmail
- From: szamla-bot@company.com
- To: {Vendor Email}
- CC: accounting@company.com (optional)
↓
8. Update Missing_Invoices Sheet
- Set "Email Elküldve" = Current Timestamp
- Increment "Ismétlési Számláló" += 1
↓
9. Update NAV_Data Status: "🔴 Hiányzik - Email Elküldve"
↓
10. Log Action to Audit_Log

## Page 6

- Columns: Timestamp, Invoice Number, Action, Result
6. HUMAN INTERVENTION SCENARIOS
Automation hands off to humans when:
Scenario 1: Unrecognized Vendor
Trigger: Vendor Tax ID not in vendor master list, no email found
Action:
• Flag in NAV_Data: "⚪ Manuális Ellenőrzés - Új Szállító"
• Send Slack/Email notification to Accounting Manager
• Include: Vendor Name, Tax ID, Invoice Amount
• Request: Add vendor email to system
Scenario 2: Unparseable PDF
Trigger: OCR confidence < 80% or critical fields (Invoice Number, Amount) missing
Action:
• Move PDF to "/Manual_Review/" folder
• Add row to Received_PDFs with Status: "Kézi Feldolgozás Szükséges"
• Send email to accounting: "Please manually extract data from attached PDF"
Scenario 3: Vendor Doesn't Respond (3+ emails)
Trigger: Ismétlési Számláló >= 3
Action:
• Set "Kézi Beavatkozás Kért" = TRUE
• Send notification: "Vendor {Name} has not responded after 3 automated emails. Consider phone call or
alternative contact."
• Escalate to Procurement/Vendor Management team
Scenario 4: Dispute/Wrong Invoice
Trigger: Vendor replies claiming "invoice was cancelled" or "sent to wrong company"
Action:
• Gmail Rule: Watch for replies containing keywords ("tévedés", "mégsem", "rossz cím")
• Label email: "🔍 Vitás Számla"
• Forward to Accounting Manager

## Page 7

• Add comment in Missing_Invoices sheet
• Pause automation for this invoice
Scenario 5: Amount Mismatch
Trigger: Received PDF amount differs from NAV XML by >5%
Action:
• Flag: "⚠️ Összeg Eltérés"
• Send alert with comparison:
NAV XML: 120,000 HUF
Received PDF: 150,000 HUF
Difference: +30,000 HUF (25%)
• Request manual verification
7. FAILURE HANDLING
Error Type 1: Email Delivery Bounce
Problem: Vendor email bounces (invalid address)
Detection: Gmail API returns bounce notification
Response:
1. Update Missing_Invoices
- Set "Email Státusz" = "Bounce - Hibás Email"
2. Increment error counter
3. [IF first bounce]
→ Try alternative email format (e.g., info@vendor.com)
4. [IF second bounce]
→ Set "Kézi Beavatkozás Kért" = TRUE
→ Notify human: "Please find correct contact for {Vendor}"
Error Type 2: NAV API Timeout
Problem: NAV API doesn't respond (rate limit 429 or timeout)
Detection: HTTP status code 429 or 504
Response:
1. Log error to Audit_Log
- Timestamp, Error Code, Message
2. Wait 4 seconds (NAV penalty delay)
3. Retry with exponential backoff:
- Attempt 1: 4 sec wait
- Attempt 2: 10 sec wait
- Attempt 3: 30 sec wait
4. [IF 3 retries fail]
→ Skip this sync cycle

## Page 8

→ Send admin notification: "NAV API unavailable. Will retry in next scheduled run (tomorrow 7 AM)."
→ Continue with remaining invoices
Error Type 3: Google Drive Storage Full
Problem: Cannot upload PDF (quota exceeded)
Detection: Drive API returns 403 Forbidden (quota)
Response:
1. Send URGENT notification to IT Admin
- Subject: "ACTION REQUIRED: Drive storage full - Invoice automation paused"
2. Store PDF temporarily in Make/Zapier file storage (24 hours)
3. Add row to Received_PDFs with Drive Link = "PENDING - Storage Full"
4. Pause ingestion branch (disable trigger)
5. [Once resolved]
→ Manually re-process pending PDFs
→ Re-enable trigger
Error Type 4: Malformed Data (Invalid Invoice Number)
Problem: NAV returns invoice number with unexpected format (e.g., "ABC/2025/##INVALID##")
Detection: Regex validation fails
Response:
1. Don't add to NAV_Data sheet
2. Add to separate "Errors" sheet with:
- Raw XML snippet
- Error reason: "Invalid format"
- Timestamp
3. Send weekly digest to admin (not immediate alert)
4. Continue processing other invoices
Error Type 5: Sheet Corruption/Accidental Deletion
Problem: Someone deletes critical rows from sheets
Detection: Row count drops unexpectedly (>10% decrease in one day)
Response:
1. Make automatic backup before each daily sync
- Copy entire workbook to "/Backups/NAV-Recon-YYYY-MM-DD.xlsx"
2. Send alert: "WARNING: {X} rows disappeared from NAV_Data. Backup created. Please verify."
3. Pause automation
4. Request admin to restore or confirm intentional deletion
8. PLAIN LANGUAGE BUILD PROMPT

## Page 9

Copy-Paste Ready Prompt for No-Code Developer or AI
PROJECT TITLE: Hungarian Invoice Reconciliation Automation System
GOAL:
Create an automated system that:
1. Tracks invoices that Hungarian tax authority (NAV) says exist
2. Monitors which actual PDF invoices our company has received
3. Automatically emails vendors when we're missing their invoice PDF
4. Logs everything so accountants can see what's happening
TOOLS TO USE:
• Gmail (email address: szamla-bot@company.com)
• Google Sheets (one workbook with 4 tabs)
• Make.com or Zapier (choose Make for complex logic)
SHEET STRUCTURE:
Create one Google Sheets workbook called "NAV-Invoice-Reconciliation" with 4 tabs:
Tab 1: NAV_Data
Columns:
• Invoice Number (text)
• Vendor Name (text)
• Vendor Tax ID (text)
• Net Amount (number)
• VAT Amount (number)
• Gross Amount (number)
• Performance Date (date)
• Invoice Date (date)
• Currency (text, usually "HUF")
• NAV Fetch Time (datetime - auto-filled)
• Status (dropdown: "In Progress", "PDF Received", "Missing - Email Sent", "Manual Review")
Tab 2: Received_PDFs
Columns:
• Invoice Number (text)
• Vendor Name (text)
• Amount (number)

## Page 10

• Received Date (datetime - auto-filled)
• Gmail Message ID (text - auto-filled)
• Drive File Link (URL - auto-filled)
• Processor (text - "Automation" or person's name)
• Notes (text)
Tab 3: Missing_Invoices
Columns:
• Invoice Number (text)
• Vendor Name (text)
• Vendor Email (text)
• Amount (number)
• Missing Detected (datetime)
• Email Sent (datetime)
• Reminder Count (number, default 0)
• Manual Intervention Needed (checkbox)
Tab 4: Audit_Log
Columns:
• Timestamp (datetime)
• Invoice Number (text)
• Action (text - what the automation did)
• Result (text - success/error)
• Error Details (text)
AUTOMATION #1: CATCH INCOMING INVOICE EMAILS
When: An email arrives at szamla-bot@company.com
What to do:
Step 1: Check if the email has a PDF attachment
• If NO attachment → Skip and do nothing
• If YES → Continue to Step 2
Step 2: Download the PDF file from the email
Step 3: Upload the PDF to Google Drive
• Folder path: "/NAV_Invoices/Received_PDFs/2025-12/" (use current year-month)
• File name format: "InvoiceNumber_VendorName_Date.pdf"
Step 4: Try to read text from the PDF (use OCR tool in Make/Zapier)

## Page 11

• Look for: Invoice number (usually starts with "Számlaszám:" or has pattern like "INV-2025-001")
• Look for: Amount (number followed by "Ft" or "HUF")
• Look for: Vendor name (top of invoice)
Step 5: Add a new row to the "Received_PDFs" sheet:
• Fill in: Invoice Number, Vendor Name, Amount (from PDF)
• Fill in: Received Date (use current timestamp)
• Fill in: Gmail Message ID (from email metadata)
• Fill in: Drive File Link (the URL from Step 3)
• Fill in: Processor = "Automation"
Step 6: Label the Gmail email as "✅ Processed"
Step 7: Check if this invoice number exists in "NAV_Data" sheet
• If YES → Update that row's Status column to "PDF Received"
• If NO → Do nothing (might be an invoice we sent out, not received)
Step 8: If the invoice was in "Missing_Invoices" sheet, delete that row (problem solved!)
Error handling:
• If PDF can't be read (OCR fails) → Add email label "⚠️ Manual Review Needed" and add note in
Received_PDFs sheet
• If file name already exists in Drive → Add timestamp to make it unique
(InvoiceNumber_VendorName_Date_HH-MM.pdf)
AUTOMATION #2: DAILY MISSING INVOICE CHECK
When: Every day at 7:00 AM Budapest time
What to do:
Step 1: Get all rows from "NAV_Data" sheet where Status is NOT "PDF Received"
Step 2: For each invoice in that list:
Step 2a: Search for its Invoice Number in "Received_PDFs" sheet
Step 2b: If FOUND in Received_PDFs:
→ Update NAV_Data Status to "PDF Received"
→ Move to next invoice
Step 2c: If NOT FOUND in Received_PDFs:
→ This invoice is missing! Continue to Step 3
Step 3: Check if this invoice is already in "Missing_Invoices" sheet
Step 3a: If NOT in Missing_Invoices yet:
→ Add new row with Invoice details
→ Set Reminder Count = 0
→ Continue to Step 4

## Page 12

Step 3b: If ALREADY in Missing_Invoices:
→ Check the "Reminder Count" number
→ If count is 3 or more:
→ Check the "Manual Intervention Needed" box
→ Send email to accounting manager: "Vendor hasn't responded after 3 emails. Please call them."
→ STOP automation for this invoice
→ If count is less than 3 AND more than 3 days have passed since "Email Sent" date:
→ Add 1 to Reminder Count
→ Continue to Step 4
→ If less than 3 days passed:
→ Skip this invoice (wait longer before resending)
Step 4: Send missing invoice email to vendor
Step 4a: Look up vendor email address (you'll need a separate "Vendors" sheet with Tax ID and Email columns)
Step 4b: If no email found:
→ Update Status in NAV_Data to "Manual Review - No Email"
→ Send notification to accounting
→ Skip to next invoice
Step 4c: If email exists, send this email:
**To:** Vendor Email
**From:** szamla-bot@company.com
**Subject:** Missing Invoice - [Invoice Number]
**Body:**
```
Dear [Vendor Name],
According to the Hungarian Tax Authority (NAV) online system,
you issued the following invoice to our company:
- Invoice Number: [Invoice Number]
- Amount: [Gross Amount] HUF
- Performance Date: [Performance Date]
However, we have not received the PDF invoice document yet.
Please reply to this email with the invoice attached, or upload it here:
[Link to Google Form for upload]
Thank you for your cooperation!
Best regards,
[Company Name] Finance Department
(This is an automated message)
```
Step 4d: Update "Missing_Invoices" sheet:
→ Set "Email Sent" to current timestamp
→ Add 1 to "Reminder Count"
Step 4e: Update "NAV_Data" Status to "Missing - Email Sent"
Step 4f: Add entry to "Audit_Log":
→ Timestamp = now

## Page 13

→ Invoice Number = [Invoice Number]
→ Action = "Sent missing invoice email to [Vendor Name]"
→ Result = "Success" (or error message if email failed)
Step 5: After processing all invoices, send summary email to accounting manager:
Subject: Daily Invoice Reconciliation Summary
Total invoices in NAV: [X]
PDFs received: [Y]
Missing invoices: [Z]
Emails sent today: [N]
Manual review needed: [M]
See full details in the Google Sheets workbook.
Error handling:
• If NAV API doesn't respond → Log error, skip this run, try again tomorrow
• If email bounces → Update Missing_Invoices with "Email Failed - Bounce" in Notes column
• If Gmail API quota exceeded → Log error, send urgent alert to IT admin
AUTOMATION #3: HANDLE VENDOR REPLIES
When: A reply arrives to an email sent by szamla-bot@company.com
What to do:
Step 1: Check if reply has PDF attachment
• If YES → Run the same steps as Automation #1 (treat it like a new incoming invoice)
• If NO → Continue to Step 2
Step 2: Check email content for keywords:
• Keywords indicating problem: "tévedés" (mistake), "mégsem" (cancelled), "rossz cím" (wrong address),
"nem mi" (not us)
If problem keywords found:
→ Add Gmail label "🔍 Disputed Invoice"
→ Forward email to accounting manager
→ Add note in Missing_Invoices sheet: "Vendor disputes this invoice"
→ Stop automation for this invoice number
Step 3: If no attachment and no problem keywords:
→ Add Gmail label "📝 Vendor Response - No Attachment"
→ Send auto-reply: "Thank you for your response. However, we still need the PDF invoice. Please attach it to your
next email."
WHEN HUMANS NEED TO STEP IN:
The automation will notify humans (send email to accounting@company.com) when:
1. New vendor not in database - automation can't find email address
→ Human must add vendor email to "Vendors" sheet

## Page 14

2. PDF can't be read - OCR fails or PDF is scanned image with low quality
→ Human must manually type invoice number and amount
3. Vendor doesn't respond after 3 emails - automation gives up
→ Human should call vendor or find alternative contact
4. Amount doesn't match - PDF shows different amount than NAV data (>5% difference)
→ Human must investigate (maybe partial payment, credit note, or error)
5. Technical errors - NAV API down, Google Drive full, Gmail quota exceeded
→ Human (IT admin) must fix infrastructure issue
HOW TO SET THIS UP IN MAKE.COM:
Scenario 1: "Invoice Email Ingestion"
1. Add module: Gmail > Watch Emails
o Configure: Watch label "INBOX", filter "has:attachment filename:pdf"
2. Add module: Gmail > Get an Email
3. Add router with 2 paths:
o Path 1: If attachment exists → Continue
o Path 2: If no attachment → Stop
4. Add module: Gmail > Download an Attachment
5. Add module: Google Drive > Upload a File
6. Add module: Google Cloud Vision > OCR (or Make's "Parse Document")
7. Add module: Google Sheets > Add a Row (to Received_PDFs)
8. Add module: Gmail > Add a Label to Email ("✅ Processed")
9. Add module: Google Sheets > Search Rows (in NAV_Data, by Invoice Number)
10. Add router:
o If found → Update Row (set Status = "PDF Received")
o If not found → Do nothing
11. Add module: Google Sheets > Search Rows (in Missing_Invoices)
12. Add module: Google Sheets > Delete a Row (if found in Missing_Invoices)
Scenario 2: "Daily Reconciliation"
1. Add module: Schedule > Every Day (7:00 AM, Europe/Budapest timezone)
2. Add module: Google Sheets > Get Range Values (NAV_Data, all rows where Status != "PDF Received")
3. Add module: Iterator (process each row one by one)
4. Inside iterator:
o Add module: Google Sheets > Search Rows (Received_PDFs, match Invoice Number)
o Add router with 2 paths:
▪ Path A: If found → Update NAV_Data Status

## Page 15

▪ Path B: If not found → Continue to next step
o Add module: Google Sheets > Search Rows (Missing_Invoices, match Invoice Number)
o Add router with 3 paths:
▪ Path 1: If NOT in Missing_Invoices → Add Row
▪ Path 2: If in Missing_Invoices AND Reminder Count < 3 → Continue
▪ Path 3: If Reminder Count >= 3 → Update "Manual Intervention" checkbox, send notification
o Add module: Google Sheets > Search Rows (Vendors sheet, match Vendor Tax ID)
o Add module: Gmail > Send an Email (use template from Step 4c above)
o Add module: Google Sheets > Update a Row (Missing_Invoices, increment counter)
o Add module: Google Sheets > Add a Row (Audit_Log)
5. After iterator ends:
o Add module: Gmail > Send an Email (summary report to accounting manager)
Scenario 3: "Handle Replies"
1. Add module: Gmail > Watch Emails
o Configure: Watch "Sent" folder, filter "is:reply to:vendor_email"
2. Add router with 3 paths:
o Path A: If has attachment → Trigger Scenario 1
o Path B: If body contains "tévedés|mégsem|rossz cím" → Add label, forward to human
o Path C: Otherwise → Send auto-reply requesting attachment
TESTING CHECKLIST:
Before going live, test these scenarios:
☐ Send test email with PDF to szamla-bot@company.com → Check if it appears in Received_PDFs sheet
☐ Manually add invoice to NAV_Data that's NOT in Received_PDFs → Wait for daily run, check if email sent
☐ Send same test invoice 4 times → Verify reminder count increases and manual flag set at 3
☐ Send email with no attachment → Verify it's labeled correctly and skipped
☐ Send email with unreadable PDF (blank page) → Check if flagged for manual review
☐ Reply to automation email without attachment → Verify auto-reply sent
☐ Add invoice to NAV_Data, then to Received_PDFs → Check if Status updates to "PDF Received"
MAINTENANCE:
• Weekly: Check Audit_Log for errors
• Monthly: Review "Manual Review" items and clear resolved ones
• Quarterly: Update email templates if needed (e.g., language improvements)
• Yearly: Archive old invoices (move PDFs older than 8 years to cold storage per Hungarian law)

## Page 16

That's the complete system! Copy this entire prompt to a no-code developer or AI assistant, and they should be
able to build the automation without additional questions.
ADDITIONAL IMPLEMENTATION NOTES
Data Privacy & Security:
• Use Google Workspace Business to ensure GDPR compliance
• Enable 2-factor authentication on szamla-bot@company.com
• Restrict Sheet edit permissions (automation has Editor role, humans have Viewer role)
• Never store NAV API keys in sheets (use Make's secure credential storage)
Scalability Considerations:
• For >1000 invoices/month, consider upgrading to Make's Pro plan for higher operation limits
• Implement pagination when fetching NAV data (API returns max 100 records per call)
• Use Google Sheets API batching for bulk updates to avoid rate limits
Hungarian-Specific Compliance:
• PDF retention period: 8 years (Számviteli Törvény)
• Ensure Drive folder has automatic backup to separate Google account (disaster recovery)
• For eÁFA integration later, this system's data can be exported to NAV's M2M interface
This system addresses the exact pain point identified in your market analysis: the gap between NAV's XML data
and companies' physical invoice possession, enabling proactive compliance before the September 2025 penalty
enforcement.
⁂
1. NAV-szamlaegyeztetes-KKV-piac-elemzese.docx
