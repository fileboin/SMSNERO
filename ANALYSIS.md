# SMSNero — Analiza stabilnosti i Escrow sistem

## 1. Arhitektura projekta

SMSNero je monolitna Node.js aplikacija koja nudi iznajmljivanje telefonskih
brojeva za primanje OTP poruka. Plaćanje se vrši putem Bitcoin Lightning mreže
(Swiss Bitcoin Pay). Ceo backend, frontend (SPA u jednom HTML stringu), baza
podataka (PostgreSQL, šema se kreira pri pokretanju) i WebSocket server nalaze
se u jednoj datoteci: **`server.cjs`** (~1 650 linija).

### Tehnološki stack

| Sloj | Tehnologija |
|------|-------------|
| Runtime | Node.js (CommonJS) |
| Web framework | Express 4 |
| Baza podataka | PostgreSQL (`pg`) |
| Real-time | WebSocket (`ws`) |
| Plaćanje | Swiss Bitcoin Pay (Lightning) |
| SMS provideri | SMSPool, 5sim (DB-konfigurabilni adapteri) |
| Auth | Custom HMAC-SHA256 JWT (bez `jsonwebtoken` paketa) |
| SMS outbound | MacroDroid polling (Android) |
| Deployment | Render.com (hardkodirani fallback URL) |

---

## 2. Analiza stabilnosti — pronađeni problemi

### 🔴 Kritično (funkcionalnost odmah narusena)

#### [C-1] OTP poruke brisane posle 1 minute *(POPRAVLJENO)*
```
// Staro:
await pool.query("DELETE FROM messages WHERE created_at < NOW() - INTERVAL '1 minute'");
// interval pokretanja: svakih 30 sekundi!
```
Poruke su brisane svakih 30 sekundi — korisnik je imao manje od 1 minute da vidi
primljeni OTP. Ovo je fundamentalni bag koji čini servis neupotrebljivim.

**Popravka:** Interval se sada izvršava svakih 30 minuta a OTP-ovi se čuvaju 24 sata.

#### [C-2] Kupac (buyer) ne dobija refund na wallet po escrow sporu *(POPRAVLJENO)*
U `POST /api/admin/resolve/:txId` kada admin odabere `winner: "buyer"`, stari kod
je samo postavljao status na `'refunded'` — nikada nije kreditovao buyer-ov
wallet. Sredstva su efektivno nestajala.

**Popravka:** Sada se pun iznos (`amount_sats`) atomično upisuje na buyer-ov wallet
pre promene statusa.

#### [C-3] Lažna DB transakcija u referral kodu *(POPRAVLJENO)*
```js
// Staro (POGREŠNO — BEGIN i ostali upiti idu na RAZLIČITE konekcije iz pool-a!):
await pool.query("BEGIN");
await pool.query("INSERT INTO user_referrals ...");
await pool.query("UPDATE wallets ...");
await pool.query("COMMIT");
```
Svaki `pool.query()` uzima proizvoljnu konekciju iz pool-a. `BEGIN` i `COMMIT`
nisu bili na istoj konekciji, pa transakcija **nikad nije bila stvarna**. Ovo je
moglo dovesti do duplog trošenja referral bonusa ili parcijalno primenjenih
promena.

**Popravka:** Koristi se eksplicitna `client = pool.connect()` konekcija.

#### [C-4] Race condition pri skidanju novca s walleta *(POPRAVLJENO)*
```js
// Staro (TOCTOU — između SELECT i UPDATE drugi request može isprazniti wallet):
const bal = wr.rows[0]?.balance_sats || 0;
if (bal >= price) {
  await client.query("UPDATE wallets SET balance_sats = balance_sats - $1 ...", [price]);
}
```
**Popravka:** Atomički UPDATE sa ugrađenim uslovom:
```sql
UPDATE wallets SET balance_sats = balance_sats - $1
WHERE user_id = $2 AND balance_sats >= $1
RETURNING balance_sats
```
Provera `rowCount > 0` potvrđuje uspeh.

---

### 🟠 Visok prioritet (sigurnost/pouzdanost)

#### [H-1] Webhooks bez verifikacije potpisa *(POPRAVLJENO)*
Oba webhook endpointa (`/webhook` i `/api/webhook/:txId`) prihvatali su **bilo
koji POST zahtev** bez provere da li dolaze od Swiss Bitcoin Pay. Napadač je
mogao poslati lažnu `status: "paid"` notifikaciju i dobiti uslugu besplatno.

**Popravka:** Dodata `verifyWebhookSignature()` funkcija koja proverava
`x-sbp-signature` / `x-webhook-signature` header sa HMAC-SHA256 korišćenjem
`SWISS_SECRET_KEY`. Ako ključ nije konfigurisan, verifikacija se preskače uz
`console.warn` (radi kompatibilnosti sa starim deploymentima).

#### [H-2] JWT tokeni nikad ne ističu *(POPRAVLJENO)*
```js
// Staro: nema 'exp' polja u payload-u
signToken({ id: user.id, username: user.username, role: user.role })
```
Ukradeni token bio je važeći zauvek.

**Popravka:** Dodato `exp: now + 90_dana` i `iat: now` u svaki token.
`verifyToken()` sada proverava `exp` i baca grešku `"Token expired"`.

#### [H-3] Admin korisnik `id: 0` nije u bazi
```js
const user = { id: 0, username: "admin", role: "admin" };
```
Admin ID 0 ne postoji u `users` tabeli. Svaki FK constraint koji referencira
`user_id` prskaće ako admin nekad pokuša akciju koja kreira DB red (escrow,
wallet, itd.).

**Preporuka:** Kreirati stvarnog admin usera u `users` tabeli pri `initDb()` ako
ne postoji, ili zaštititi sve admin rute od akcija koje zahtevaju FK.

#### [H-4] `SWISS_SECRET_KEY` obavezan, ali `signPayload()` nikad nije pozivan
Aplikacija ne starta bez `SWISS_SECRET_KEY`, ali ta promenljiva se koristila
samo u `signPayload()` koji je bio mrtav kod. Sada se koristi za verifikaciju
webhook potpisa (vidi H-1).

#### [H-5] JWT token u URL query stringu (MacroDroid)
```
GET /api/pending-sms?key=<JWT_TOKEN>
```
Token se pojavljuje u server logovima, browser istoriji i Referer headerima.

**Preporuka:** Prebaciti na `Authorization: Bearer` header ili koristiti
poseban API ključ za MacroDroid integraciju.

---

### 🟡 Srednji prioritet (robusnost)

#### [M-1] Dvostruki P2P payment put u frontend-u
U JS kodu unutar HTML-a postoje dve funkcije:
- `escrowBuyP2P(listingId)` → poziva `/api/buy` (ispravni escrow put)
- `buyP2P(id)` → poziva `/create-invoice` s `p2pListingId` (stari put bez escrow-a)

Stari put (`buyP2P`) dodeljivao je samo 50% prihoda vlasniku broja umesto 92%
koji se koriste u escrow sistemu. Na P2P tržištu se prikazuje dugme koje poziva
`escrowBuyP2P`, ali `buyP2P` ostaje dostupna i može biti pozvana direktno.

**Preporuka:** Ukloniti `buyP2P` funkciju ili je preusmeriti na `escrowBuyP2P`.

#### [M-2] SSL `rejectUnauthorized: false` u produkciji
```js
ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
```
Onemogućava verifikaciju SSL sertifikata baze. Potrebno za Render.com (self-signed
cert), ali otvara mogućnost man-in-the-middle napada na DB konekciju.

**Preporuka:** Koristiti root CA sertifikat Render-a umesto `rejectUnauthorized: false`.

#### [M-3] Automatski release escrow-a ignoriše greške unutar petlje
```js
for (const tx of result.rows) {
  await releaseFunds(tx); // ako ovo baci grešku za jedan tx, cela petlja se prekida
  console.log("Auto-released escrow:", tx.id);
}
```
**Preporuka:** Omotati svaki `releaseFunds(tx)` u try/catch unutar petlje.

#### [M-4] Provider polling — nedostaje filtriranje po provideru
```js
const provider = await getActiveProvider(); // uvek isti (prvi aktivni)
// ...ali sessija može imati sessija.provider !== provider.provider_type
const result = await providerCheckSMS(provider, sess.provider_order_id);
```
Ako se aktivni provider promeni, stare sesije će pokušati da polluju pogrešan
provider API sa tuđim `orderId`-jem.

**Preporuka:** Joinovati `sessions` sa `sms_providers` tabelom ili čuvati
`provider_id` u sesiji.

#### [M-5] In-memory rate limiting ne radi na više instanci
`rateBuckets` Map se resetuje pri restartu i nije podeljen između instanci.

**Preporuka:** Koristiti Redis ili PostgreSQL-based rate limiting za produkciju.

#### [M-6] BTC kurs hardkodiran na $65,000 kao fallback
```js
let _btcRate = 65000;
```
Ako eksternog poziv za BTC kurs ne uspe, cene se računaju po stalom kursu.

---

### 🔵 Niski prioritet (code quality / ops)

| Šifra | Problem |
|-------|---------|
| L-1 | Monolitna ~1 650-linijska datoteka (UI, API, DB, plaćanje sve u jednoj) |
| L-2 | `index.html` i `style.css` su orphaned fajlovi — nisu servirani aplikacijom |
| L-3 | `node server.cjs` (sa razmakom u imenu) je zastarela kopija sa sintaksnom greškom i `/download-source` endpointom koji izlaže izvorni kod |
| L-4 | Nema `.env.example` dokumentacije |
| L-5 | Nema migracionih fajlova — šema se kreira inline SQL-om pri pokretanju |
| L-6 | Celokupni SPA HTML string (>1200 linija) šalje se pri svakom `GET /` bez kešinga |
| L-7 | Celo novosti povlačenje (`fetchNews`) koristi callback-based `https.get` umesto async `fetch` |

---

## 3. Escrow sistem — detaljna analiza

### 3.1 Status implementacije

Escrow sistem **postoji i funkcionalan je** za osnove. Implementiran je u okviru
P2P marketplace funkcionalnosti.

### 3.2 Dijagram toka

```
Buyer                    server.cjs                Swiss Bitcoin Pay         Seller
  |                          |                              |                   |
  |-- POST /api/buy -------->|                              |                   |
  |   { listingId }          |-- POST /checkout ----------->|                   |
  |                          |<-- { paymentRequest, id } ---|                   |
  |<-- { txId, QR } ---------|                              |                   |
  |                          |                              |                   |
  |== PAY Lightning ========>==================== (Lightning network) =========>|
  |                          |<-- POST /api/webhook/:txId --|                   |
  |                          |   { status: "paid" }         |                   |
  |                          |-- status='paid' -> DB        |                   |
  |                          |-- broadcast(escrow_paid) --->| <-- WS notif      |
  |                          |                              |                   |
  | (Buyer receives OTP)     |                              |                   |
  |                          |                              |                   |
  +-- Option A: Confirm ---->|                              |                   |
  |   POST /api/confirm/:id  |-- releaseFunds() ------------|------------------>|
  |                          |   wallet += seller_amount    |                   |
  |                          |   status='released'          |                   |
  |                          |                              |                   |
  +-- Option B: Dispute ---->|                              |                   |
  |   POST /api/dispute/:id  |-- status='disputed'          |                   |
  |                          |-- broadcast(escrow_disputed) |                   |
  |                          |                              |         Admin      |
  |                          |<-- POST /api/admin/resolve/:id (winner=buyer|seller)
  |                          |-- if buyer: wallet += amount_sats (POPRAVLJENO)  |
  |                          |-- if seller: releaseFunds()  |                   |
  |                          |                              |                   |
  +-- Option C: No action    |                              |                   |
     (auto-release after 30 min via setInterval)            |                   |
                             |-- releaseFunds() -> seller   |                   |
```

### 3.3 Tabela `escrow_transactions`

```sql
CREATE TABLE IF NOT EXISTS escrow_transactions (
  id             TEXT PRIMARY KEY,           -- 32-char hex random
  listing_id     BIGINT REFERENCES p2p_listings(id) ON DELETE SET NULL,
  buyer_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
  seller_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  amount_sats    INTEGER NOT NULL,           -- pun iznos koji je kupac platio
  seller_amount  INTEGER NOT NULL,           -- 92% → seller wallet
  commission     INTEGER NOT NULL,           -- 8% → platforma zadržava
  invoice_id     TEXT,                       -- Swiss Bitcoin Pay checkout ID
  payment_request TEXT,                     -- Lightning BOLT11 invoice
  status         TEXT NOT NULL DEFAULT 'pending',
  dispute_reason TEXT,
  created_at     BIGINT NOT NULL,            -- Unix ms
  paid_at        BIGINT,
  released_at    BIGINT
);
```

**Mogući statusi:** `pending → paid → released | disputed → released | refunded`

### 3.4 Provizija

```js
const commission = Math.ceil(sats * 0.08);  // 8% platforma
const sellerAmount = sats - commission;      // 92% prodavac
```

Platforma zadržava proviziju — ona ne odlazi nikome, samo se ne prosljeđuje.
Prihod od provizije je vidljiv putem `/admin/stats` (escrow transakcije
doprinose `p2p_revenue`).

### 3.5 Pronađeni bugovi pre popravki

| Bug | Opis | Status |
|-----|------|--------|
| **Buyer refund** | `winner=buyer` postavljao samo status='refunded', bez kreditiranja walleta | **POPRAVLJENO** |
| **Dual P2P put** | `buyP2P()` poziva `/create-invoice` umesto `/api/buy` (nema escrow-a) | Otvoreno (vidi M-1) |
| **Auto-release greška** | Greška u jednoj tx prekida celu petlju auto-releasea | Otvoreno (vidi M-3) |
| **Lažna DB transakcija** | Referral bonus nije bio u pravoj transakciji | **POPRAVLJENO** |

### 3.6 Šta je ispravno u escrow implementaciji

- ✅ Atomičan `releaseFunds()` — koristi `INSERT ... ON CONFLICT DO UPDATE` za wallet
- ✅ Zaštita od samokupovine: `if (buyerId === item.user_id) return 400`
- ✅ Auto-release posle 30 minuta (zaštita sellera)
- ✅ WebSocket notifikacije za sve strane u realnom vremenu
- ✅ Admin može ručno rešiti sporove

---

## 4. Pregled primenjenih popravki

| ID | Problem | Fajl | Linija (pre) |
|----|---------|------|--------------|
| C-1 | OTP poruke brisane za 1 min | `server.cjs` | ~303 |
| C-2 | Buyer ne dobija refund na wallet | `server.cjs` | ~1497 |
| C-3 | Lažna DB transakcija u referralu | `server.cjs` | ~1351 |
| C-4 | TOCTOU wallet race condition | `server.cjs` | ~924, ~950 |
| H-1 | Webhooks bez verifikacije | `server.cjs` | ~949, ~1466 |
| H-2 | JWT bez `exp` polja | `server.cjs` | ~43 |

---

## 5. Preporučene naredne akcije (van ovog PR-a)

1. **[H-3]** Kreirati stvarnog admin usera u `users` tabeli pri inicijalizaciji
2. **[M-1]** Ukloniti `buyP2P()` funkciju iz frontend-a (dupli put)
3. **[M-3]** Omotati svaki `releaseFunds(tx)` u try/catch u auto-release petlji
4. **[M-4]** Popraviti provider polling — filtrirati sesije po tipu providera
5. **[H-5]** MacroDroid auth — prebaciti token iz URL query stringa
6. **[L-3]** Obrisati `node server.cjs` fajl (sintaksna greška + source leak)
7. Dodati `.env.example` sa svim varijablama
8. Razmotriti Redis za shared rate limiting pri skaliranju
