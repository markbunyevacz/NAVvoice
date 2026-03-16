# Business Case: NAVvoice – Automatizált Hiányszámla-Egyeztető Middleware

**Verzió:** 1.0
**Dátum:** 2026. március 16.
**Státusz:** Döntéshozatalra előkészítve
**Bizalmasság:** Belső

---

## 1. Vezetői összefoglaló

A NAVvoice egy SaaS-alapú pénzügyi middleware, amely a magyar vállalkozások legfájóbb, eddig megoldatlan adóügyi problémájára ad választ: a NAV Online Számla rendszerében látható, de a vállalkozó könyvelésébe be nem érkezett („hiányzó") számlák automatizált detektálására és pótlásának agentic AI-alapú vezérlésére.

A belépési feltételek most ideálisak. A NAV 2025 szeptemberétől WARN → ERROR szintre emelte a korábbi figyelmeztetések 15 kategóriáját, ezzel kötelező jelleggel kikényszerítve az adatszolgáltatás pontosságát. Egyidejűleg az eÁFA-rendszer kiterjesztése az éves bevallókra lezárta a "teljes kört", ahol minden eltérés blokkoló tétellé válik. Ez a szabályozói kényszer ~250 000 aktív KKV-t érint, és azonnali, specifikus megoldás iránti keresletet teremt, amelyre a piacon jelenleg nincs dedikált válasz.

A NAVvoice ezt a rést tölti be: nem könyvelőprogram, hanem egy proaktív „számlaüldöző" réteg, amely a NAV API és a vállalkozó rendszerei között helyezkedik el, és Google Gemini AI-vezérelt agentic workflow-val önállóan kommunikál a szállítókkal a hiánypótlás érdekében.

**Kért döntés:** Az MVP fejlesztési fázis (3 hónap) elindítása és az első pilotprogram (10 KKV) engedélyezése.

---

## 2. A probléma

### 2.1 A strukturális rés

Magyarország 2024–2025-re Európa egyik legfejlettebb valós idejű adatszolgáltatási (RTIR) ökoszisztémáját építette ki. A rendszer logikája szerint a NAV látja a szállító által beküldött összes számlát – de a vevő vállalkozóhoz sokszor nem jut el a fizikai vagy digitális bizonylat.

Ez a rés három forrásból táplálkozik:

- **Fizikai dokumentumvesztés** – különösen az építőiparban, ahol a számlák helyszíni konténerekben, személyautókban kallódnak el, miközben az XML már ott van a NAV-nál.
- **Szervezeti fragmentáció** – a könyvelő csak hetente vagy havonta kap dokumentumokat; a vállalkozó valós idejű rálátása nincs.
- **Nagy tranzakciós volumen** – a kereskedőcégek havi több ezer számlát kezelnek; a kézzel való egyeztetés szisztematikusan alulteljesít.

### 2.2 Pénzügyi és jogi következmény

Az eltérésnek azonnali következményei vannak:

| Kockázat | Összeg / hatás |
|---|---|
| Mulasztási bírság hibás / hiányzó adatszolgáltatásért | Akár **1 000 000 Ft / számla** |
| Elveszített ÁFA-levonási jog (pl. 200 000 Ft + ÁFA anyagszámla) | **54 000 Ft** egyetlen tételnél |
| eÁFA bevallás-blokkolás | Könyvelési határidő csúszás, kamat, bírság |
| Lánctartozás kockázat (csődbe ment alvállalkozó XML-je megvan, PDF nincs) | Áfa-visszaigénylés elvesztése |

**2025. szeptember 15. után** ezek a kockázatok nem elméleti forgatókönyvek: a NAV rendszere visszautasítja a hibás XML-t, és a mulasztás automatikusan rögzített.

---

## 3. A megoldás

### 3.1 Rendszerkoncepció

A NAVvoice egy négy rétegből álló middleware:

```
NAV Online Számla API 3.0
        ↓  (API hívás / webhook, MVP; Fázis 2: ütemezett)
  Egyeztető Motor
  [XML ↔ PDF gap detektálás]
        ↓  (ha hiány)
  AI Agent Orchestrator
  [Gemini: kontextus elemzés + email generálás]
        ↓  (humán jóváhagyás)
  Approval Queue → Szállítói értesítés
        ↓  (szállító PDF-et küld vissza)
  Document Ingestion Service
  [OCR / szövegkinyerés → párosítás → lezárás]
```

### 3.2 Kulcsfunkciók

**Proaktív hiánydetektálás** – Az MVP-ben a szinkronizálás API-híváson keresztül, manuálisan vagy webhook triggerrel indítható. Ha egy XML-hez nem tartozik PDF a belső tárhelyen, automatikusan „MISSING" státuszt kap. Fázis 2-ben ütemezett háttérfolyamat (APScheduler vagy Celery Beat) bevezetése várható.

**AI Invoice Chasing (Gemini)** – Az AI agent elemzi a kontextust (rendszeres partner? korábbi késések? összeg nagysága?), majd megszemélyesített, magyar nyelvű emlékeztetőt generál a szállítónak. A hangnem fokozatosan eszkalálható: POLITE → FIRM → URGENT → FINAL WARNING.

**Human-in-the-loop jóváhagyás** – Minden kimenő kommunikáció az `ApprovalQueue`-n keresztül megy; a pénzügyes vagy könyvelő jóváhagyja vagy módosítja, mielőtt az email kimegy.

**Pre-validáció** – A rendszer a 2025 szeptemberi szigorítások (hibakód 330, 596, 1150 stb.) alapján előszűri a szállítóktól várható XML-eket, és figyelmeztet, mielőtt a NAV bírságolna.

**Építőipari project mapping** – A Gemini AI az XML `lineDescription` mezőjéből munkaszámhoz / projekthez rendeli a tételeket.

### 3.3 Technológiai verem

| Komponens | Technológia |
|---|---|
| NAV API kliens | Python, SHA3-512 XML aláírás, rate limit queue |
| AI agent | Google Gemini 1.5 Flash / 2.0 (Vertex AI) |
| Backend | Python / FastAPI |
| Adatbázis | SQLite (MVP) → PostgreSQL (prod) |
| Secrets kezelés | Google Cloud Secret Manager |
| PDF feldolgozás | PyPDF2 + pytesseract OCR |
| Auth | JWT + RBAC (ADMIN / ACCOUNTANT / SITE_MANAGER) |
| Frontend (roadmap) | React (web) + React Native (mobil) |

A kódalap jelen állapota: **6 400 sor production Python**, 70 átmenő unit teszt, TOGAF-kompatibilis architektúra dokumentáció.

---

## 4. Piaci lehetőség

### 4.1 Célpiac mérete

| Szegmens | Aktív cégek (HU) | Elsődleges fájdalompont |
|---|---|---|
| Építőipari KKV | ~50 000 | Fizikai dokumentumvesztés, fordított adózás, projektelszámolás |
| Kereskedelmi KKV | ~80 000 | Nagy volumen, raktár vs. számla egyeztetés |
| Egyéb KKV (eÁFA-köteles) | ~120 000 | eÁFA bevallásblokkolás megelőzése |
| **Összesített TAM** | **~250 000 vállalkozás** | |

A Digiméter 2024 szerint a szektoriális digitalizáció 40-es indexen stagnál – nem az igény hiánya, hanem a megfelelő, specifikus megoldás hiánya miatt.

### 4.2 Piaci ablak

A 2025 szeptemberi NAV szigorítás **kényszerhelyzetet** teremtett. A versenytársak (SmartBooks, Billcity, QUiCK) általános könyvelési eszközök; a dedikált „invoice chasing" middleware niche-ben **nincs közvetlen versenytárs**.

---

## 5. Versenykörnyezet

| Szolgáltató | Fókusz | Hiányszámla kezelés | Árazás | Gyengeség |
|---|---|---|---|---|
| SmartBooks | Könyvelő szoftver | Van (automatikus rögzítés) | ~28 000 Ft/hó | Bonyolult, drága, könyvelői fókusz – nem operatív "chaser" |
| Billcity | OCR + NAV integráció | Van (NAV-ból dolgozik) | Csomag alapú | OCR a fő fókusz, automatizált üldözés korlátozott |
| QUiCK / Riport.app | Pénzügyi dashboard | Van (cash-flow) | Mikrovállalkozásokra | Nincs munkaszám / projekt egyeztetés |
| Hagyományos ERP-k | Könyvelőprogramok | Van (manuális) | Könyvelőirodai eszköz | Legacy felület, nincs valós idejű vállalkozói rálátás |
| **NAVvoice** | **Dedicated middleware** | **Proaktív + AI-vezérelt** | **14 900 Ft/hó (Builder)** | **MVP fázisban** |

**USP:** Az egyetlen megoldás, amely nem passzívan listáz, hanem agentic AI-val aktívan kommunikál a szállítókkal a pótlás érdekében, és ezt human-in-the-loop jóváhagyással teszi auditálhatóvá.

---

## 6. Üzleti modell

### 6.1 Árazás (SaaS, havi előfizetés)

| Csomag | Célcsoport | Nettó havi díj | Tartalom |
|---|---|---|---|
| **Starter** | Mikrovállalkozások, egyéni vállalkozók | **4 900 Ft** | Max. 50 bejövő számla/hó. NAV szinkron, manuális egyeztetés, Excel export. |
| **Builder** | Építőipari KKV-k | **14 900 Ft** | Max. 500 számla/hó. AI Invoice Chasing, projektkezelés, mobil app. |
| **Enterprise** | Kereskedelmi láncok, nagykereskedők | **49 000 Ft+** | Korlátlan számla, ERP API integráció, M2M eÁFA, dedikált account manager. |

### 6.2 Bevételi projekció

| | Hónap 6 | Hónap 12 | Hónap 24 |
|---|---|---|---|
| Starter (4 900 Ft) | 50 ügyfél | 200 ügyfél | 600 ügyfél |
| Builder (14 900 Ft) | 30 ügyfél | 120 ügyfél | 400 ügyfél |
| Enterprise (49 000 Ft+) | 2 ügyfél | 10 ügyfél | 40 ügyfél |
| **MRR** | **~790 000 Ft** | **~3 300 000 Ft** | **~11 000 000 Ft** |
| **ARR** | **~9,5 M Ft** | **~39,6 M Ft** | **~132 M Ft** |

*Konzervatív szcenárió, 0,03–0,16%-os penetráció a TAM-ban.*

### 6.3 Ügyfél ROI kalkuláció

Egyetlen 200 000 Ft + ÁFA (54 000 Ft ÁFA tartalmú) anyagköltség számla „megmentése" fedezi a Builder csomag ~3,6 havi díját. Egy 500 000 Ft-os NAV-bírság elkerülése fedezi ~33 havi előfizetést – az értékajánlat 10:1 feletti ROI-t képvisel.

---

## 7. Go-to-Market stratégia

**Beachhead market:** Építőipari KKV-k (Builder csomag).

**Csatornák:**
- Könyvelőirodák partnerprogram – „bizalmi híd": a könyvelő ajánlja ügyfeleinek.
- Iparági szövetségek: ÉVOSZ (Építési Vállalkozók Országos Szövetsége) és regionális kamarák.
- Digitális hirdetések: Google / Meta, célzás adószám-köteles vállalkozásokra.
- Content marketing: NAV-változásokra fókuszáló cikkek, amelyek a problémát és a megoldást együtt kommunikálják.

**Freemium kapunyitó:** Az első 100 számla ellenőrzése ingyenes – ez eltávolítja a kipróbálási akadályt, és valódi értéket mutat a konverzió előtt.

---

## 8. Kockázatok és mitigáció

| Kockázat | Valószínűség | Hatás | Mitigáció |
|---|---|---|---|
| NAV API változás / leállás | Közepes | Magas | Retry mechanizmus, offline mód belső DB-ből, GitHub changelog monitorozás |
| KKV bizalmatlanság (NAV kulcsok átadása) | Magas | Magas | ISO 27001 célkitűzés, GCP Secret Manager, freemium, könyvelői partnerprogram |
| Piaci adopció lassúsága | Közepes | Közepes | Freemium + pilot, alacsony Starter belépési ár |
| AI hallucináció az email generálásban | Alacsony | Közepes | Human-in-the-loop ApprovalQueue – minden kimenő email jóváhagyásköteles |
| GDPR / NIS2 megfelelőség | Közepes | Magas | Adatvédelmi hatásvizsgálat (DPIA), titkosított tároló, audit trail minden művelethez |
| Élő API tesztek hiánya (jelenlegi gap) | Magas | Magas | **Azonnali prioritás:** NAV teszt hitelesítőadatok beszerzése, `test_nav_live_api.py` futtatása |

---

## 9. Fejlesztési ütemterv és befektetési igény

### 9.1 Fázisok

| Fázis | Időtartam | Mérföldkő | Státusz |
|---|---|---|---|
| **Fázis 0 – Megalapozás** | Lezárva | 6 400 sor kód, 70 unit teszt, TOGAF architektúra | ✅ Kész |
| **Fázis 1 – MVP** | 1–3. hónap | NAV live API validáció, alapfunkciók, minimál dashboard | 🔄 Folyamatban |
| **Fázis 2 – Pilot** | 4. hónap | 10 építőipari KKV ingyenes pilot, visszajelzésgyűjtés | ⏳ Tervezett |
| **Fázis 3 – Go-to-Market** | 5–6. hónap | Builder csomag élesítése, könyvelői partnerprogram indítása | ⏳ Tervezett |
| **Fázis 4 – Skálázás** | 7–12. hónap | Enterprise csomag, ERP integráció, React frontend | ⏳ Tervezett |

### 9.2 Kritikus blokker (azonnali teendő)

> **A NAV élő API tesztek (`test_nav_live_api.py`) nulla lefutással rendelkeznek.** Ez az egyetlen technikai akadálya az MVP validálásának. Szükséges: NAV fejlesztői / sandbox hitelesítőadatok és egy technikai felhasználó regisztrálása a NAV felületén.

### 9.3 Becsült fejlesztési költség (Fázis 1–3)

| Tétel | Összeg (nettó) |
|---|---|
| Backend fejlesztés, tesztelés, live API integráció | ~2 000 000 Ft |
| Frontend (minimál dashboard, React) | ~1 500 000 Ft |
| Infrastruktúra (GCP, Secret Manager, tesztelés) | ~300 000 Ft |
| Jogi és compliance (GDPR DPIA, adatkezelési tájékoztató) | ~400 000 Ft |
| Marketing (pilot, tartalom, ÉVOSZ kapcsolatépítés) | ~500 000 Ft |
| **Összesen (Fázis 1–3)** | **~4 700 000 Ft** |

**Megtérülési pont:** ~320 Builder csomag ügyfél (kb. 12. hónap konzervatív szcenárióban).

---

## 10. Következtetés és kért döntés

A NAVvoice egy időkritikus piaci ablakra épülő, megalapozott technológiai alapokon álló megoldás. A befektetési igény mérsékelt (~4,7 M Ft), a potenciális éves bevétel 24 hónapon belül elérheti a 130 M Ft-ot. Az ügyfelek számára az értékajánlat 10:1 feletti ROI-t jelent már az első megmentett számlánál.

**Kért döntés:**

1. ✅ Az MVP fázis (1–3. hónap) fejlesztési keretének jóváhagyása.
2. ✅ NAV technikai felhasználó regisztrációjának elindítása (élő API tesztek unblockálásához).
3. ✅ 10 pilot ügyfél azonosítása az építőipari szegmensből (ÉVOSZ kapcsolaton keresztül).

---

*Készítette: NAVvoice fejlesztői csapat | Referencia dokumentumok: `NAV számlaegyeztetés KKV piac elemzése.md`, `ARCHITECTURE_TOGAF.md`, `DEVELOPMENT_READINESS_REPORT_v2.md`, `SECURITY & THREAT ANALYSIS.md`*
