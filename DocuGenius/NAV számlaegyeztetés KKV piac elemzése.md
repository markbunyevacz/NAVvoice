Piacelemzés és Megvalósíthatósági Tanulmány: NAV Online Számla Alapú Automatizált Hiány Számla-Egyeztető Szolgáltatás

Készítette: Vezető Fintech Stratégiai Tanácsadó

Dátum: 2025. december 1.

Tárgy: Részletes piaci, technológiai és pénzügyi elemzés a magyar KKV szektor – kiemelten az építőipar és kereskedelem – számára fejlesztendő adategyeztető szolgáltatásról.

1. Vezetői Összefoglaló

Jelen tanulmány egy hiánypótló pénzügyi technológiai (Fintech) megoldás piaci létjogosultságát és megvalósíthatóságát vizsgálja, amely a Nemzeti Adó- és Vámhivatal (NAV) Online Számla rendszerének adatait felhasználva automatizálja a vállalkozások bejövő számláinak egyeztetését. A magyar gazdasági környezet 2024-2025 fordulóján kritikus digitális transzformáción megy keresztül, amelyet az eÁFA rendszer kiterjesztése és a NAV adatszolgáltatási szabályainak 2025. szeptemberi drasztikus szigorítása jellemez.1

Az elemzés rámutat, hogy a hazai kis- és középvállalkozások (KKV-k), különösen az adminisztrációs kihívásokkal küzdő építőipari és a nagy tranzakciószámmal operáló kereskedelmi szereplők számára a "hiányszámla-menedzsment" (a NAV által látott, de a könyvelésbe be nem érkezett bizonylatok kezelése) jelentős pénzügyi és jogi kockázatot hordoz. A piac ugyan telített általános számlázó- és könyvelőprogramokkal (SmartBooks, Billcity, Számlázz.hu), de hiányzik egy dedikált, "vállalkozó-fókuszú" middleware réteg, amely proaktívan, még a bevallási határidők előtt detektálja és kezeli az eltéréseket.

Technológiai oldalról a tanulmány bizonyítja, hogy a NAV Online Számla 3.0 API 3 és a legújabb generációs AI modellek (Gemini 3 DeepThink és Agentic workflows) 4 kombinációjával költséghatékonyan felépíthető egy olyan automatizált rendszer, amely nemcsak listázza a hiányokat, hanem autonóm módon kommunikál a szállítókkal a pótlás érdekében.

A pénzügyi modellezés alapján a szolgáltatás magas megtérülést (ROI) kínál a végfelhasználóknak az áfa-visszaigénylések biztosítása és a mulasztási bírságok elkerülése révén, miközben a SaaS (Software as a Service) modellben működő szolgáltató számára skálázható bevételi forrást biztosít.

2. Makrogazdasági és Szabályozói Környezet Elemzése

A szolgáltatás sikeressége szempontjából elengedhetetlen a szabályozói kényszerek és a gazdasági realitások mélyreható megértése. Magyarország az elmúlt években Európa egyik legfejlettebb valós idejű adatszolgáltatási (RTIR) ökoszisztémáját építette ki, amely most érkezik a legszigorúbb fázisához.

2.1. A NAV Online Számla Rendszer Evolúciója és a 2025-ös Szigorítások

A NAV Online Számla rendszere már nem csupán egy ellenőrzési eszköz, hanem az eÁFA alapja. A piaci szereplők számára a legkritikusabb változás 2025. szeptember 15-én lép életbe, amikor a NAV validációs mechanizmusa szintet lép.

2.1.1. A WARN-tól az ERROR-ig: A Türelmi Időszak Vége

A NAV rendszere eddig számos formai és logikai hibát "WARN" (figyelmeztetés) üzenettel fogadott be, ami lehetővé tette, hogy a hibás adatszolgáltatások is technikailag "sikeresnek" minősüljenek. Ez a gyakorlat hamis biztonságérzetet adott a vállalkozásoknak.

Változás: 2025. szeptember 15-től 15 korábbi WARN üzenet, valamint új validációs szabályok ERROR (blokkoló hiba) státuszúvá válnak.1

Implikációk: Olyan gyakori hibák, mint a 330 (hibás teljesítési időszak dátumok), az 1150 (irreális sorszámok) vagy az 596 (belföldi fordított adózás hibás vevő adatai) esetén a NAV szervere elutasítja a számla befogadását.2

Piaci Hatás: Egy elutasított XML nem minősül teljesített adatszolgáltatásnak. Ez számlánként akár 1 millió forint mulasztási bírságot jelenthet a vállalkozások számára.1 A javasolt szolgáltatás egyik kulcsfunkciója éppen ezen hibák "pre-validációja" és a partnerek figyelmeztetése lehet, még mielőtt a NAV bírságolna.

2.1.2. Az eÁFA Rendszer Kiterjesztése

Az eÁFA rendszer 2024-es bevezetése 6 alapjaiban változtatta meg a könyvelési paradigmát. A havi és negyedéves bevallók után 2025-ben az éves bevallók csatlakozása zárja a kört.

Adatvezérelt Bevallás: Az eÁFA lényege, hogy a NAV a nála lévő adatokból (Online Számla, Pénztárgép) elkészíti a bevallás tervezetét. A probléma ott keletkezik, ahol a NAV lát egy bejövő számlát (mert a szállító beküldte), de a vállalkozó nem (mert elvesztette a papírt, vagy nem adta át a könyvelőnek).

A "Rés" (Gap): Az eÁFA rendszerben ezek a tételek eltérésként jelennek meg, blokkolva a bevallás automatikus elfogadását. A tervezett szolgáltatás ezt a "rést" hivatott betömni a bevallási időszak előtt.

2.2. Jogi Környezet: Számviteli Bizonylat vs. XML Adat

A megvalósíthatóság egyik leggyakoribb kérdése, hogy az XML adat önmagában helyettesíti-e a hagyományos számlát. A jogi helyzet kettős, és ez definiálja a szoftver működési logikáját.

1. táblázat: Jogi követelmények összehasonlítása

A NAV állásfoglalása szerint 9 a számlaadási kötelezettség teljesítése (XML beküldés) nem mentesít a bizonylat kiállítása és átadása alól. Ezért a szolgáltatás nem "könyvelhet" kizárólag az XML alapján, hanem hiánypótló eszközként kell működnie: az XML-t használja referenciának (Master Data), és ehhez kéri be a hiteles bizonylatot.

3. Ágazati Mélyelemzés és Piaci Igények

A magyar KKV szektor digitalizációs szintje alacsony, a Digiméter 2024 index 40-es értéken stagnál.11 Ez a stagnálás azonban nem az igény hiányát, hanem a megfelelő, specifikus megoldások hiányát jelzi. A tanulmány két kiemelt szektorra, az építőiparra és a kereskedelemre fókuszál.

3.1. Építőipar: A Kockázatos Óriás

Az építőipar a tervezett szolgáltatás elsődleges célcsoportja ("Beachhead Market"), mivel itt a legmagasabb az adminisztrációs káosz és a pénzügyi kockázat találkozása.

3.1.1. Gazdasági Helyzetkép és Felszámolási Hullám

A szektor súlyos kihívásokkal küzd. 2024 végén a termelés volumene csökkenő tendenciát mutatott (decemberben -4,2% év/év) 12, miközben a felszámolások száma rekordokat döntött.

Inszolvencia Statisztikák: Az Opten adatai szerint 2024-ben több mint 4000 építőipari vállalkozás került felszámolás alá 13, és a cégek száma 2,3%-kal csökkent.14 Ez a magas fluktuáció növeli a "lánctartozások" kockázatát: ha egy alvállalkozó csődbe megy, és nem küldi meg a számlát (vagy annak bizonylatát), a fővállalkozó áfa-levonási joga veszélybe kerül.

Szerződésállomány Paradoxon: Bár a termelés csökkent, a szerződésállomány volumene 40,9%-kal nőtt.15 Ez azt jelenti, hogy munka van, de a likviditás és a kivitelezés akadozik. A hatékony cash-flow menedzsment (aminek alapja a számlák megléte) élet-halál kérdés.

3.1.2. Specifikus Fájdalompontok (Pain Points)

Fizikai Dokumentumvesztés: Az építőipar decentralizált. A számlák gyakran építésvezetők autóiban, konténerekben vagy munkásruhák zsebében kallódnak el. A NAV Online Számla rendszerében ezek a számlák "látszanak", de a könyvelő nem kapja meg őket.

Megoldás: A rendszer automatikusan jelzi a cégvezetőnek: "A NAV szerint a Tüzép Kft. kiszámlázott 500.000 Ft-ot tegnap. Hol a papír?"

Fordított Adózás Kezelése: Az építési-szerelési munkák jelentős része fordított adózás alá esik. A NAV 3.0 validáció (pl. 596-os hibakód) szigorúan szűri, ha a vevő nem belföldi áfaalany, vagy ha egyenesen számláznak fordított helyett.2 A rendszer képes lehet az XML alapján előszűrni ezeket a hibákat.

Projekt Elszámolás (Munkaszámok): A cégeknek tudniuk kell, melyik költség melyik projekthez tartozik. A NAV XML lineDescription mezője gyakran tartalmazza a projekt helyszínét vagy kódját. A rendszer AI-alapú szövegelemzéssel (Gemini 3 DeepThink) automatikusan projektekhez rendelheti a költségeket.

3.2. Kereskedelem: A Volumen és az Automatizáció Kihívása

A kereskedelmi szektorban a problémát nem a dokumentumok elvesztése, hanem a tranzakciók kezelhetetlen mennyisége okozza.

3.2.1. Digitális Érettség és Integrációs Igény

A Digiméter kutatása szerint a kereskedelem a leginkább digitalizált ágazatok közé tartozik.16 Ez előny, mert a szereplők nyitottak a technológiára, ugyanakkor elvárás a meglévő rendszerekkel (ERP, Webshop motor) való integráció.

3.2.2. A "Nagy Volumen" Probléma

M2M Kényszer: Az eÁFA webes felülete csak 100.000 bizonylat alatt használható, efelett kötelező a gép-gép kapcsolat.6 A közepes és nagy kereskedőcégek (wholesale, e-commerce) könnyen átlépik ezt a határt.

Készlet vs. Számla: A kereskedelemben a bejövő számlát gyakran össze kell vetni a raktárbevételezéssel. Ha a NAV-ban megjelenik egy számla, de a raktárkészletben nincs nyoma az árunak, az belső visszaélésre vagy adminisztrációs hibára utalhat. A szolgáltatás "elő-auditor" funkciója itt kritikus lehet.

4. Versenytárs Elemzés és Piaci Pozícionálás

A magyar piacon számos érett szoftver létezik, de ezek többsége a "könyvelő" szemszögéből közelít, nem a "vállalkozó" igényeiből indul ki a hiánypótlás terén.

4.1. Főbb Piaci Szereplők Összehasonlítása

2. táblázat: Versenytárs Mátrix

4.2. A Tervezett Szolgáltatás USP-je (Unique Selling Proposition)

A javasolt megoldás nem kíván teljes körű könyvelőprogram lenni. Ehelyett egy speciális middleware, amely a NAV Online Számla és a vállalkozó (vagy könyvelője) között helyezkedik el.

Proaktív "Invoice Chasing" (Számlaüldözés): A rendszer nemcsak listázza a hiányt, hanem cselekszik is. Agentic workflow segítségével 21 automatikusan emailt generál a szállítónak: "Tisztelt Partnerünk! A NAV rendszerében látjuk a X sorszámú számláját, de a PDF bizonylat nem érkezett meg. Kérjük, töltse fel ide..."

Építőipari "Terep-kompatibilitás": Mobil-first megközelítés. Az építésvezető a helyszínen megkapja az értesítést a hiányzó számláról, és azonnal fotózhatja/feltöltheti, ha nála van.

Technológiai Előny (Gemini 3): A piacon egyedülálló módon a rendszer a legújabb AI modelleket használja a számlatételek értelmezésére és a manuális adatrögzítés kiváltására (lásd 5. fejezet).

5. Technológiai Megvalósíthatóság és AI Implementáció

A szolgáltatás technikai gerincét a NAV API 3.0 és a Google Gemini 3 modellcsaládjának integrációja adja. Ez a kombináció teszi lehetővé a magas fokú automatizációt és a költséghatékony üzemeltetést.

5.1. NAV API Architektúra és Korlátok Kezelése

A NAV Online Számla rendszeréhez való kapcsolódás szigorúan szabályozott. A fejlesztés során a következő technikai paramétereket kell figyelembe venni:

Végpont: A /queryInvoiceData operáció szolgál a bejövő (szállítói) számlák lekérdezésére.3

Rate Limiting (Forgalomkorlátozás): A NAV rendszere IP-címenként másodpercenként 1 kérést engedélyez. Túlterhelés esetén 4000 ms késleltetést ("büntetést") alkalmaz.23

Megoldás: A rendszernek egy aszinkron, sorba állított (queue-based) lekérdezési motort kell használnia. Nem valós időben, hanem ütemezve (pl. éjszaka vagy 4 óránként) frissíti az adatokat, elkerülve a 429-es hibákat.

Technikai Felhasználó: Az ügyfeleknek létre kell hozniuk egy technikai felhasználót a NAV felületén 24, és megadniuk a kulcsokat a szoftvernek. A kulcsok (XML aláírókulcs, cserekulcs) tárolása kritikus biztonsági kérdés (titkosított Vault használata kötelező).

5.2. AI-Vezérelt Automatizáció (Gemini 3 DeepThink & Agentic)

A szolgáltatás innovációs értékét a mesterséges intelligencia alkalmazása adja, amely túlmutat az egyszerű szabályalapú rendszereken. A kutatási anyagok alapján a Gemini 3 modellcsalád 4 képességei közvetlenül alkalmazhatók a problémára.

5.2.1. "Vibe Coding" a Gyors Piacra Lépésért

A fejlesztési fázisban a Gemini 3 "vibe coding" képessége 5 lehetővé teszi az MVP (Minimum Viable Product) rendkívül gyors előállítását. Ahelyett, hogy heteket töltenénk a boilerplate kód írásával, a fejlesztők természetes nyelven instruálhatják a modellt a frontend (Dashboard) és a backend (NAV API konnektor) vázának létrehozására. Ez drasztikusan csökkenti a fejlesztési költségeket és a Time-to-Market időt.

5.2.2. Agentic Workflow a Hiánypótláshoz

A rendszer nem egy passzív adatbázis, hanem egy "ügynök" (Agent).21

Működési Elv:

Detektálás: A rendszer észleli, hogy a NAV-ban van XML, de a belső tárhelyen nincs PDF.

Döntés (DeepThink): A Gemini 3 DeepThink modulja 29 elemzi a szituációt. (Pl. "Ez egy rendszeres havi számla? Múlt hónapban mikor érkezett? Ki a kapcsolattartó?")

Cselekvés: Az Agent automatikusan generál egy megszemélyesített emailt a szállítónak 30, csatolva a hiányzó számla adatait (sorszám, összeg, teljesítés dátuma), és kérve a pótlást.

Feldolgozás: Ha a szállító válaszol a PDF-fel, az Agent automatikusan feldolgozza, párosítja az XML-lel, és lezárja az ügyet ("Ticket Closed").

5.2.3. SOP Generálás Rendezetlen Adatokból

Az építőiparban gyakori, hogy a folyamatok nincsenek dokumentálva. A Gemini 3 képes a meeting leiratokból vagy a szétszórt emailekből strukturált Standard Operating Procedure (SOP) dokumentumokat generálni.32 Ez a szolgáltatás "bónusz" modulja lehet, segítve a cégeket a belső adminisztrációs rend kialakításában.

6. Üzleti Modell és Pénzügyi Terv

A szolgáltatás bevezetése SaaS (Software as a Service) modellben javasolt, amely biztosítja a kiszámítható, visszatérő árbevételt (MRR).

6.1. Árazási Stratégia

A versenytársak árazása 17 és a piaci fizetőképesség alapján három csomag kialakítása javasolt:

3. táblázat: Javasolt Árazási Csomagok

Összehasonlításképp: A SmartBooks Business Pro csomagja évi ~338.000 Ft (kb. 28.000 Ft/hó).17 A javasolt "Builder" csomag feleannyiba kerül, miközben specifikusabb (építőipari) funkcionalitást kínál.

6.2. Megtérülés (ROI) a Felhasználó Számára

Miért éri meg az előfizetés az ügyfélnek?

ÁFA Visszaigénylés: Egyetlen "megmentett" (időben előkerített), 200.000 Ft + ÁFA értékű anyagköltség számla esetén az 54.000 Ft visszanyert ÁFA fedezi közel 4 hónap előfizetési díját.

Bírságkockázat Csökkentése: A 2025. szeptemberi szigorítások miatt 1 a hibás adatszolgáltatás kockázata nő. A rendszer "Pre-Check" funkciója segít elkerülni az akár 1 millió forintos bírságokat.

Adminisztrációs Idő: Az automatizált email küldés (Agentic workflow) havonta több órányi manuális adminisztrációt spórol meg az irodavezetőnek vagy a könyvelőnek.

7. Kockázatelemzés és Mitigációs Stratégiák

7.1. Technológiai Függőségek

Kockázat: A NAV Online Számla rendszerének leállása vagy API változása.

Mitigáció: Folyamatos nyomon követése a NAV fejlesztői dokumentációjának (GitHub).36 Robusztus hibakezelés (Retry mechanism) beépítése a szoftverbe, hogy a NAV kimaradások alatt is működőképes maradjon a belső adatbázisból.

7.2. Piaci Adoptáció és Bizalom

Kockázat: A KKV szektor bizalmatlansága az "újabb szoftverekkel" szemben és az adatbiztonsági félelmek (NAV kulcsok átadása).

Mitigáció: "Freemium" modell alkalmazása (az első 100 számla ellenőrzése ingyenes). Transzparens adatkezelési tájékoztató, és ISO 27001 vagy hasonló biztonsági tanúsítványok megszerzése/kommunikálása. Partnerség építése könyvelőirodákkal, akik "bizalmi hídként" ajánlják a szoftvert ügyfeleiknek.

8. Következtetés és Javasolt Lépések

A piacelemzés és a technológiai vizsgálat alapján a NAV Online Számla alapú hiányszámla-egyeztető szolgáltatás fejlesztése kifejezetten ajánlott. A piaci "ablak" (Market Window) most nyitott a legszélesebbre: az eÁFA bevezetése és a 2025. szeptemberi szigorítások kényszerhelyzetet teremtenek, amire a jelenlegi piac (SmartBooks, Billcity) csak részleges, gyakran túlbonyolított választ ad.

Azonnali Teendők (Action Plan):

MVP Fejlesztés (Hónap 1-3): A Gemini 3 "vibe coding" segítségével 26 egy gyors prototípus elkészítése, amely csak a NAV bejövő számlák listázását és a PDF feltöltés/pipálás funkciót tudja.

Pilot Program (Hónap 4): 10 kiválasztott építőipari KKV bevonása ingyenes tesztelésre, cserébe visszajelzésért.

Go-to-Market (Hónap 6): Indulás a "Builder" csomaggal, fókuszálva az építőipari szakportálokon és szövetségeken (ÉVOSZ) keresztüli kommunikációra.

Ez a stratégia minimalizálja a fejlesztési kockázatot, miközben maximalizálja a piaci penetráció esélyét egy olyan szegmensben, amely éhezik az egyszerű, de hatékony megoldásokra.

Works cited

NAV Online Számla rendszer – 2025. szeptember 15-től újabb szigorítások léptek életbe, accessed December 1, 2025, https://www.rsm.hu/blog/adotanacsadas/nav-online-szamla-rendszer-szeptembertol-ujabb-szigoritasok

NAV Online Számla rendszer változások 2025 - Grant Thornton Hungary, accessed December 1, 2025, https://grantthornton.hu/hirek/nav-online-szamla-rendszer-valtozasok-2025

Online Szamla - Interfesz Specifikáció - EN - v3.0 PDF - Scribd, accessed December 1, 2025, https://www.scribd.com/document/488013348/Online-Szamla-Interfesz-specifikacio-EN-v3-0-pdf

Google’s Gemini 3 is winning over tech CEOs, researchers: Here’s what they are saying, accessed December 1, 2025, https://indianexpress.com/article/technology/artificial-intelligence/google-gemini-3-winning-over-tech-ceos-researchers-10385557/

Gemini 3.0 Just DESTROYED All Vibe Coding Tools… and It's FREE - YouTube, accessed December 1, 2025, https://www.youtube.com/watch?v=sc5S-xQWifA

NAV: benyújtható a bevallás az eÁFA-rendszerben - Önadózó, accessed December 1, 2025, https://www.onadozo.hu/hirek/nav-benyujthato-a-bevallas-az-eafa-rendszerben-12653

bizonylati rend | csfk, accessed December 1, 2025, https://csfk.hun-ren.hu/csfkwp/wp-content/uploads/2015/07/CSFK_bizonylati_rend_2015_sk.pdf

BIZONYLATI REND - Arany János Közösségi Ház és Városi Könyvtár, accessed December 1, 2025, https://www.gyalikozhaz.hu/dokumentumok/2021%20-%20bizonylati%20szablyzat.doc.pdf

1 A számla, nyugta kibocsátásának alapvető szabályai (Közzétéve - NAV, accessed December 1, 2025, https://nav.gov.hu/pfile/file?path=/ugyfeliranytu/nezzen-utana/inf_fuz/rejtett/Informacios-fuzetek---Aktualis/18.-informacios-fuzet---A-szamla-nyugta-kibocsatasanak-alapveto-szabalyai

Az elektronikus számlákkal kapcsolatos legfontosabb tudnivalók - Nemzeti Adó - NAV, accessed December 1, 2025, https://nav.gov.hu/ado/afa/Az_elektronikus_szaml20200416

Digiméter 2024: Digitális felzárkózás helyett visszarendeződés - Budapesti Kereskedelmi és Iparkamara, accessed December 1, 2025, https://bkik.hu/hirek/sajtokozlemenyek/digimeter-2024-digitalis-felzarkozas-helyett-visszarendezodes

Decemberben is vergődött a hazai építőipar - Telex, accessed December 1, 2025, https://telex.hu/gazdasag/2025/02/14/epitoipari-termeles-december-ksh

OPTEN » Címke: felszámolás, accessed December 1, 2025, https://www.opten.hu/cimke/felszamolas

500 új cég és 2,3%-os cégszámcsökkenés: Merre tart az építőipar? - OPTEN, accessed December 1, 2025, https://www.opten.hu/kozlemenyek/500-uj-ceg-es-23os-cegszamcsokkenes-merre-tart-az-epitoipar

Kilőtt a magyar építőipar szeptemberben, de csalóka a kép - 444, accessed December 1, 2025, https://444.hu/2025/11/14/kilott-a-magyar-epitoipar-szeptemberben-de-csaloka-a-kep

Digiméter 2024: a kereskedőcégek jobban digitalizáltak - Kosárérték.hu, accessed December 1, 2025, https://kosarertek.hu/konverzio/digimeter-2024-a-kereskedocegek-jobban-digitalizaltak/

SMARTBooks Business, accessed December 1, 2025, https://hello.smartbooks.hu/business/

Előfizetési csomagok - Billcity, accessed December 1, 2025, https://help.billcity.hu/hc/hu/articles/360021255460-El%C5%91fizet%C3%A9si-csomagok

Könyvelő vagyok, Billcity-t használok, kacsintgassak-e a QUiCK-kel?, accessed December 1, 2025, https://helloquick.riport.app/post/k%C3%B6nyvel%C5%91-vagyok-billcity-t-haszn%C3%A1lok-kacsingassak-e-a-quick-kel

Integrált pénzügyi nyilvántartási program (IPTAX) - Novitax, accessed December 1, 2025, https://novitax.hu/szoftvereink/integralt-penzugyi-nyilvantartasi-program-iptax/

Gemini 3.0 and the Rise of AI Agents — How Automation Changes Everything | by Julian Goldie | Oct, 2025, accessed December 1, 2025, https://medium.com/@julian.goldie/gemini-3-0-and-the-rise-of-ai-agents-how-automation-changes-everything-1e183ed8a7b5

Online - Szamla - Interfesz Specifikacio - HU - v3.0 | PDF - Scribd, accessed December 1, 2025, https://www.scribd.com/document/556975056/Online-Szamla-interfesz-specifikacio-HU-v3-0

Online Szamla - Interfesz Specifikáció - EN - v3.0 PDF - Scribd, accessed December 1, 2025, https://www.scribd.com/document/488013144/Online-Szamla-Interfesz-specifikacio-EN-v3-0-pdf

NAV online invoice registration - Google Sites, accessed December 1, 2025, https://sites.google.com/dupplak.com/nav-oir

Gemini 3 Pro Preview – Vertex AI - Google Cloud Console, accessed December 1, 2025, https://console.cloud.google.com/vertex-ai/publishers/google/model-garden/gemini-3-pro-preview

Vibe coding with Gemini 3 in AI Studio, accessed December 1, 2025, https://www.youtube.com/watch?v=Pb6XHGi542A

How to Vibe Code with Gemini 3 PRO and BUILD 3 Applications (for FREE), accessed December 1, 2025, https://www.youtube.com/watch?v=9qmQED6uIRg&vl=es

Gemini Agent - AI automation for daily tasks & multi-step work, accessed December 1, 2025, https://gemini.google/overview/agent/

A new era of intelligence with Gemini 3 - Google Blog, accessed December 1, 2025, https://blog.google/products/gemini/gemini-3/

About Google Workspace Flows, accessed December 1, 2025, https://sites.google.com/view/workspace-flows/about

Build your own agents in Google Workspace Flows - Lead with AI, accessed December 1, 2025, https://www.leadwithai.co/article/build-your-own-agents-in-google-workspace-flows

Build your own reusable AI study assistant with Gems to turn messy notes into perfect study guides - YouTube, accessed December 1, 2025, https://www.youtube.com/watch?v=P9WRqxyh19M

How to Use Gemini to take notes | Beginner to Advanced - YouTube, accessed December 1, 2025, https://www.youtube.com/watch?v=ZRgTrvwAoJs

Prompt Engineering for Gemini: The Skills Google Wants You to Learn - The AI Hustle Guy, accessed December 1, 2025, https://www.aihustleguy.com/blog/prompt-engineering-for-gemini

Pricing Plans: Choose the Perfect Solution for Your Business - SmartBook, accessed December 1, 2025, https://smartbook.cloud/prices

Felkészülés az eÁFA használatára - Nemzeti Adó- és Vámhivatal, accessed December 1, 2025, https://nav.gov.hu/print/ado/eafa/informaciok/Felkeszules_az_eAFA_hasznalatara

pzs/nav-online-invoice - GitHub, accessed December 1, 2025, https://github.com/pzs/nav-online-invoice

| Szempont | Hagyományos (Papír/PDF) Számla | NAV XML Adatállomány | Tervezett Szolgáltatás Megközelítése |
| --- | --- | --- | --- |
| Számviteli Törvény (Szt.) | Hiteles bizonylat, a könyvelés alapja.7 | Önmagában nem minősül számviteli bizonylatnak (kivéve archiválás). | Az XML csak "ellenőrző lista", a cél a PDF megszerzése. |
| Áfa Törvény | Adólevonási jog tárgyi feltétele.9 | Adatszolgáltatás, nem maga a számla. | Figyelmeztet, ha van XML, de nincs PDF (ÁFA kockázat). |
| Megőrzési Kötelezettség | Eredeti formában megőrzendő.10 | A NAV szerverein tárolódik, de a cégnek is archiválnia kellene. | Digitális archívum létrehozása a megszerzett PDF-ekből. |

| Szolgáltató | Fő Profil | NAV Integráció | Hiányszámla Kezelés | Árazás & Célcsoport | Hiányosságok a Célpiacon |
| --- | --- | --- | --- | --- | --- |
| SmartBooks | Könyvelés-támogató szoftver | Magas (Számlázz.hu + NAV) | Van (automatikus rögzítés) | Magas (338.000 Ft/év-től).17 Cél: Könyvelők, nagyobb KKV-k. | Bonyolult felület, a "Pro" csomag drága a kisebb építőipari cégeknek. Inkább könyvelési eszköz, nem operatív "chaser". |
| Billcity | Számlafeldolgozó (OCR+NAV) | Közepes/Magas | Van (NAV adatokból dolgozik) | Csomag alapú.18 Cél: Digitális könyvelők. | Az OCR a fő fókusz, nem a hiánypótlási folyamat automatizálása. A "számlaüldözés" funkció korlátozott. |
| QUiCK (Riport.app) | Pénzügyi Dashboard | Magas | Van (Cash-flow fókusz) | Mikrovállalkozásokra szabott.19 | Kiváló UX, de funkcionálisan kevés a komplex építőipari projektekhez (pl. nincs munkaszám alapú egyeztetés NAV XML-ből). |
| Hagyományos ERP-k (RLB, Novitax) | Könyvelőprogramok | Magas (Beépített modulok) | Van (de manuális) | Könyvelőirodák "belső" eszközei. | "Legacy" felületek.20 A vállalkozó nem látja valós időben, csak amikor a könyvelő lefutatja a listát. |

| Csomag | Célcsoport | Havi Díj (Nettó) | Tartalom & Funkciók |
| --- | --- | --- | --- |
| Starter (Alap) | Mikrovállalkozások, Egyéni Vállalkozók | 4.900 Ft | Max. 50 bejövő számla/hó. NAV lista szinkronizáció, manuális pipálás, Excel export. |
| Builder (Építő) | Építőipari KKV-k | 14.900 Ft | Max. 500 számla/hó. Automatikus "Invoice Chasing" email ügynök, Munkaszám/Projekt kezelés, Mobil app fotózás funkció. |
| Enterprise | Kereskedelmi láncok, Nagykereskedők | Egyedi (49.000 Ft-tól) | Korlátlan számla. ERP API integráció, M2M eÁFA támogatás, Dedikált account menedzser. |
