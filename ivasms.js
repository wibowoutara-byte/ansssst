const express = require("express");
const https   = require("https");
const zlib    = require("zlib");

const router = express.Router();

/* ================= CONFIG ================= */
const BASE_URL       = "https://www.ivasms.com";
const TERMINATION_ID = "1029603";
// PENTING: cf_clearance biasanya terikat ke fingerprint (User-Agent/TLS) saat
// challenge Cloudflare diselesaikan di browser. Kalau UA di sini beda dengan
// UA browser yang dipakai waktu login/generate cf_clearance, Cloudflare bisa
// reject meski cookie-nya masih "valid". Set via env IVAS_USER_AGENT kalau perlu.
const USER_AGENT = process.env.IVAS_USER_AGENT ||
  "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";

/* ================= COOKIES (Update when expired) =================
   PENTING: jangan hardcode cookie session di source code yang bisa ke-commit
   ke repo publik. Ambil dari environment variable, dengan fallback string
   kosong supaya endpoint /status akan bilang "session expired" alih-alih
   error aneh kalau env belum di-set.
   Set di .env:
     IVAS_XSRF_TOKEN=...
     IVAS_SESSION=...
   Jab expire ho: browser me login karo → DevTools → Network → koi bhi request
   → Request Headers → Cookie se XSRF-TOKEN aur ivas_sms_session copy karo,
   lalu update via POST /update-session atau update env var + restart.
*/
let COOKIES = {
  "XSRF-TOKEN":       process.env.IVAS_XSRF_TOKEN ||
    "eyJpdiI6ImlwcVVrQ0wzQXJoWEZ2eXNHUGp0Rmc9PSIsInZhbHVlIjoiWElUaGlTMmtYM1R6ZUNEWUNWMlQ2b0M2T0ZuRHZRNzNxeWszVzZwbTdKS2FVeEFlOEdnQWZ2MHdOTTQxbVI1b1RNOGdNcVFFMWRNeG9sbzdYMWFIYzJEbnpXYmlWREozUTdyV0xvQkcxRU90WmI3elVEM3hjbTNzTTNkOE5WYTIiLCJtYWMiOiJjMDVmYTZkYjRkN2Y0OGM2ZTQ2NmUwYzdlNjg1YWNhMTRlZTIyYTBjMDFkMGQzNzFmMGM5NDgxZjg4MGU5NGY2IiwidGFnIjoiIn0%3D",
  "ivas_sms_session": process.env.IVAS_SESSION ||
    "eyJpdiI6IlVUWElsK20wblVya2ZNelFQUXhWeXc9PSIsInZhbHVlIjoiNm1PTzVKMUM2eVhlNU8xb0dwcGxMK2NiQ1p5UHhJdnNjaUxiSnVDdHNIOXNVbGVqU2Q5MXI3Vk1mR1hkL21kcjNTbXpQU0doRzVjdUZ4RmNhUCttTEx2ZklBL0NqOUN5czhCaCtlaHpFL3pPNDBaelp5Tjh3eDhvN2JldjNUdHAiLCJtYWMiOiJkOTBjZGM1ZDMwZWY3NjhhODRkZjYyMTZhZmMyZDgyY2NmYWZhZTg1ZTQzZDdmOTk3YzkzNDYxNzA4MDA2NzZhIiwidGFnIjoiIn0%3D",
  "cf_clearance": process.env.IVAS_CF_CLEARANCE ||
    "auwwwlfhCwsT6bGpggSiBpYnSQHtKB1Iq.IYbOhMwjc-1782942460-1.2.1.1-4mKyRSddraYyyVPUxBL9_.SWeKGLTNQdo9Rq1LBbjddbtlwH.6dzh0r4vkqA6KsaIlm5Nx_J1BjpMPFSBT7muYrK8_ZgPJIbn_JUTliE2Pmgc8UHyLZASfx72VCbqBw5M01.zSiS0qOlPWg5gRn6aavy.Rw31FkchORJRLABH.zINLCmmfWaC6YDqTn0WB2.LWXViFONREh3OMdlTR68zmccf.bmq9e0HlrxiMh67uTSBI22ScXgpV_nYlJDq8n8JATfnbx5xwASzL5sjU6lfxZiuGywLlvSRJUAHPqSa44tZ4BfW8zHgUH1SXxonQKeSPl4P3K7FkOy7rmue5wJJVxcyjWXDlML2ATHXXL9Bwg1KBqHJy6gLmaJkKFhEGi724xeHu7Z4m6Xfn1H1pv_LamGLKrIlROf6V_5hD8Ju0f7NRco4sJ2O8Qp0W8IgP2jYlG98n_O3e0tCAxgPstTddbx29ul.5w2iJZZV3bNEk49Gw3H8jutCDgP6hlNA0R5"
};

// cf_clearance sengaja TIDAK diganti otomatis dari set-cookie response (biar
// tidak ketimpa oleh nilai dari halaman challenge kalau Cloudflare minta
// re-verify). Kalau expired, refresh manual sama seperti XSRF-TOKEN/session.
const AUTO_UPDATE_COOKIE_KEYS = ["XSRF-TOKEN", "ivas_sms_session"];

/* ================= HELPERS ================= */
function getToday() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function cookieString() {
  return Object.entries(COOKIES).map(([k, v]) => `${k}=${v}`).join("; ");
}

function getXsrf() {
  try { return decodeURIComponent(COOKIES["XSRF-TOKEN"] || ""); }
  catch { return COOKIES["XSRF-TOKEN"] || ""; }
}

function safeJSON(text) {
  try { return JSON.parse(text); }
  catch { return { error: "Invalid JSON", preview: text.substring(0, 300) }; }
}

/* ================= HTTP REQUEST ================= */
function makeRequest(method, path, body, contentType, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const headers = {
      "User-Agent":       USER_AGENT,
      "Accept":           "*/*",
      "Accept-Encoding":  "gzip, deflate, br",
      "Accept-Language":  "en-PK,en;q=0.9",
      "Cookie":           cookieString(),
      "X-Requested-With": "XMLHttpRequest",
      "X-XSRF-TOKEN":     getXsrf(),
      "X-CSRF-TOKEN":     getXsrf(),
      "Origin":           BASE_URL,
      "Referer":          `${BASE_URL}/portal`,
      ...extraHeaders
    };

    if (method === "POST" && body) {
      headers["Content-Type"]   = contentType;
      headers["Content-Length"] = Buffer.byteLength(body);
    }

    const req = https.request(BASE_URL + path, { method, headers }, res => {
      // Auto-update cookies from response
      if (res.headers["set-cookie"]) {
        res.headers["set-cookie"].forEach(c => {
          const sc = c.split(";")[0];
          const ki = sc.indexOf("=");
          if (ki > -1) {
            const k = sc.substring(0, ki).trim();
            const v = sc.substring(ki + 1).trim();
            if (AUTO_UPDATE_COOKIE_KEYS.includes(k)) {
              COOKIES[k] = v;
            }
          }
        });
      }

      let chunks = [];
      res.on("data", d => chunks.push(d));
      res.on("end", () => {
        let buf = Buffer.concat(chunks);
        try {
          const enc = res.headers["content-encoding"];
          if (enc === "gzip") buf = zlib.gunzipSync(buf);
          else if (enc === "br") buf = zlib.brotliDecompressSync(buf);
        } catch { /* not compressed / already plain */ }

        const text = buf.toString("utf-8");

        if (res.statusCode === 401 || res.statusCode === 419 ||
            text.includes('"message":"Unauthenticated"')) {
          return reject(new Error("SESSION_EXPIRED"));
        }

        resolve({ status: res.statusCode, body: text });
      });
    });

    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

/* ================= FETCH _token FROM PORTAL ================= */
async function fetchToken() {
  const resp = await makeRequest("GET", "/portal", null, null, {
    "Accept": "text/html,application/xhtml+xml,*/*"
  });
  const match = resp.body.match(/name="_token"\s+value="([^"]+)"/) ||
                resp.body.match(/"csrf-token"\s+content="([^"]+)"/);
  return match ? match[1] : null;
}

/* ================= PARSE HTML HELPERS ================= */
function stripHTML(html) {
  return (html || "").replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
}

/* ================= GET NUMBERS ================= */
async function getNumbers(token) {
  const ts   = Date.now();
  const path = `/portal/numbers?draw=1`
    + `&columns[0][data]=number_id&columns[0][name]=id&columns[0][orderable]=false`
    + `&columns[1][data]=Number`
    + `&columns[2][data]=range`
    + `&columns[3][data]=A2P`
    + `&columns[4][data]=LimitA2P`
    + `&columns[5][data]=limit_cli_a2p`
    + `&columns[6][data]=limit_cli_did_a2p`
    + `&columns[7][data]=action&columns[7][searchable]=false&columns[7][orderable]=false`
    + `&order[0][column]=1&order[0][dir]=desc`
    + `&start=0&length=5000&search[value]=&_=${ts}`;

  const resp = await makeRequest("GET", path, null, null, {
    "Referer":      `${BASE_URL}/portal/numbers`,
    "Accept":       "application/json, text/javascript, */*; q=0.01",
    "X-CSRF-TOKEN": token
  });

  const json = safeJSON(resp.body);
  return fixNumbers(json);
}

function fixNumbers(json) {
  if (!json || !json.data) return json;

  // Format: [range, "", number, "Weekly", ""]
  const aaData = json.data.map(row => [
    row.range || "",
    "",
    String(row.Number || ""),
    "Weekly",
    ""
  ]);

  return {
    sEcho:                2,
    iTotalRecords:        String(json.recordsTotal || aaData.length),
    iTotalDisplayRecords: String(json.recordsFiltered || aaData.length),
    aaData
  };
}

/* ================= GET SMS =================
   3 langkah, sesuai flow situs:
   1) POST getsms            -> daftar "range" (grup nomor)
   2) POST getsms/number     -> daftar nomor per range
   3) POST getsms/number/sms -> pesan OTP aktual per nomor
   Parser di bawah (parseSMSMessages) pakai selector spesifik
   (cli-tag / msg-text / time-cell) yang cocok dengan markup asli situs,
   jadi ini satu-satunya versi yang dipakai (versi fallback regex generik
   yang lama dibuang karena hasilnya kurang akurat).
*/
async function getSMS(token) {
  const today    = getToday();
  const boundary = "----WebKitFormBoundary6I2Js7TBhcJuwIqw";

  const parts = [
    `--${boundary}\r\nContent-Disposition: form-data; name="from"\r\n\r\n${today}`,
    `--${boundary}\r\nContent-Disposition: form-data; name="to"\r\n\r\n${today}`,
    `--${boundary}\r\nContent-Disposition: form-data; name="_token"\r\n\r\n${token}`,
    `--${boundary}--`
  ].join("\r\n");

  // Step 1: Get ranges
  let r1;
  try {
    r1 = await makeRequest(
      "POST", "/portal/sms/received/getsms", parts,
      `multipart/form-data; boundary=${boundary}`,
      { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01" }
    );
  } catch (e) {
    console.warn("[IVAS] Step1 (ranges) failed:", e.message);
    return { sEcho: 1, iTotalRecords: "0", iTotalDisplayRecords: "0", aaData: [], error: e.message };
  }

  const ranges = [...r1.body.matchAll(/toggleRange\('([^']+)'/g)].map(m => m[1]);
  console.log(`[IVAS] Ranges: ${ranges.join(", ")}`);

  const allRows = [];

  for (const range of ranges) {
    // Step 2: Get numbers per range
    const b2 = new URLSearchParams({ _token: token, start: today, end: today, range }).toString();
    const r2 = await makeRequest(
      "POST", "/portal/sms/received/getsms/number", b2,
      "application/x-www-form-urlencoded",
      { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01" }
    ).catch(e => { console.warn(`[IVAS] Step2 (${range}) failed:`, e.message); return null; });

    if (!r2) continue;

    // Extract numbers from HTML: toggleNum..('NUMBER','NUMBER_ID')
    const numbers = [...r2.body.matchAll(/toggleNum[^(]+\('(\d+)'/g)].map(m => m[1]);
    console.log(`[IVAS] ${range} → numbers: ${numbers.join(", ")}`);

    for (const number of numbers) {
      // Step 3: Get actual OTP SMS for each number
      const b3 = new URLSearchParams({ _token: token, start: today, end: today, Number: number, Range: range }).toString();
      const r3 = await makeRequest(
        "POST", "/portal/sms/received/getsms/number/sms", b3,
        "application/x-www-form-urlencoded",
        { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01" }
      ).catch(e => { console.warn(`[IVAS] Step3 (${range}/${number}) failed:`, e.message); return null; });

      if (!r3) continue;

      allRows.push(...parseSMSMessages(r3.body, range, number, today));
    }
  }

  return {
    sEcho:                1,
    iTotalRecords:        String(allRows.length),
    iTotalDisplayRecords: String(allRows.length),
    aaData:               allRows
  };
}

function parseSMSMessages(html, range, number, date) {
  const rows  = [];
  const clean = t => (t || "")
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&").replace(/&#039;/g, "'")
    .replace(/\s+/g, " ").trim();

  // Extract all <tr> rows (skip header)
  const trAll = [...html.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)];

  for (const trM of trAll) {
    const row = trM[1];
    if (row.includes("<th")) continue;

    // Sender from cli-tag
    const senderM = row.match(/class="cli-tag"[^>]*>([^<]+)</);
    const sender  = senderM ? senderM[1].trim() : "SMS";

    // Message from msg-text div (multiline content)
    const msgM    = row.match(/class="msg-text"[^>]*>([\s\S]*?)<\/div>/i);
    const message = msgM ? clean(msgM[1]) : "";

    // Time from time-cell
    const timeM = row.match(/class="time-cell"[^>]*>\s*([0-9:]+)\s*</);
    const time  = timeM ? timeM[1].trim() : "00:00:00";

    if (message) {
      rows.push([
        `${date} ${time}`,
        range,
        number,
        sender,
        message,
        "$",
        0
      ]);
    }
  }

  return rows;
}

/* ================= ROUTES ================= */

// Main API
router.get("/", async (req, res) => {
  const { type } = req.query;
  if (!type) return res.json({ error: "Use ?type=numbers or ?type=sms" });

  try {
    const token = await fetchToken();
    if (!token) {
      return res.status(401).json({
        error: "Session expired",
        fix:   "POST /api/ivasms/update-session with xsrf and session cookies"
      });
    }

    if (type === "numbers") return res.json(await getNumbers(token));
    if (type === "sms")     return res.json(await getSMS(token));

    res.json({ error: "Invalid type. Use numbers or sms" });

  } catch (err) {
    if (err.message === "SESSION_EXPIRED") {
      return res.status(401).json({
        error: "Session expired — update cookies",
        fix:   "POST /api/ivasms/update-session with xsrf and session"
      });
    }
    res.status(500).json({ error: err.message });
  }
});

// Raw debug: show actual OTP SMS HTML (level 3)
router.get("/raw-sms", async (req, res) => {
  try {
    const token    = await fetchToken();
    const today    = getToday();
    const boundary = "----WebKitFormBoundary6I2Js7TBhcJuwIqw";
    const parts = [
      `--${boundary}\r\nContent-Disposition: form-data; name="from"\r\n\r\n${today}`,
      `--${boundary}\r\nContent-Disposition: form-data; name="to"\r\n\r\n${today}`,
      `--${boundary}\r\nContent-Disposition: form-data; name="_token"\r\n\r\n${token}`,
      `--${boundary}--`
    ].join("\r\n");
    // Level 1
    const r1 = await makeRequest("POST", "/portal/sms/received/getsms", parts,
      `multipart/form-data; boundary=${boundary}`,
      { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01" }
    );
    const rangeMatch = r1.body.match(/toggleRange\('([^']+)'/);
    if (!rangeMatch) return res.send("No ranges:\n" + r1.body.substring(0, 1000));
    const range = rangeMatch[1];
    // Level 2
    const r2 = await makeRequest("POST", "/portal/sms/received/getsms/number",
      new URLSearchParams({ _token: token, start: today, end: today, range }).toString(),
      "application/x-www-form-urlencoded",
      { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01" }
    );
    const numMatch = r2.body.match(/toggleNum[^(]+\('(\d+)'/);
    if (!numMatch) return res.send(`Range: ${range}\nNo numbers:\n` + r2.body.substring(0, 1000));
    const number = numMatch[1];
    // Level 3
    const r3 = await makeRequest("POST", "/portal/sms/received/getsms/number/sms",
      new URLSearchParams({ _token: token, start: today, end: today, Number: number, Range: range }).toString(),
      "application/x-www-form-urlencoded",
      { "Referer": `${BASE_URL}/portal/sms/received`, "Accept": "text/html, */*; q=0.01" }
    );
    res.set("Content-Type", "text/plain");
    res.send(`Range: ${range}\nNumber: ${number}\n\n` + r3.body.substring(0, 5000));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Cookie update endpoint — POST with JSON body
// { "xsrf": "...", "session": "...", "cfClearance": "..." (optional) }
router.post("/update-session", express.json(), (req, res) => {
  const { xsrf, session, cfClearance } = req.body || {};
  if (!xsrf || !session) {
    return res.status(400).json({
      error: "Required: xsrf and session (cfClearance optional)",
      example: { xsrf: "XSRF-TOKEN value", session: "ivas_sms_session value", cfClearance: "cf_clearance value" }
    });
  }
  COOKIES["XSRF-TOKEN"]       = xsrf;
  COOKIES["ivas_sms_session"] = session;
  if (cfClearance) COOKIES["cf_clearance"] = cfClearance;
  console.log("✅ [IVAS] Cookies updated manually");
  res.json({ success: true, message: "Cookies updated!" });
});

// Check session status
router.get("/status", async (req, res) => {
  try {
    const token = await fetchToken();
    res.json({
      status:     token ? "✅ Session active" : "❌ Session expired",
      hasToken:   !!token,
      cookieKeys: Object.keys(COOKIES)
    });
  } catch (e) {
    res.json({ status: "❌ Session expired", error: e.message });
  }
});

module.exports = router;
