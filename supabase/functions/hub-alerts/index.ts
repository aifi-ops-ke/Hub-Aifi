// Hub-Aifi instant phone alerts
//
// Triggered by two Postgres triggers (via pg_net, see supabase/functions/hub-alerts/webhook.sql)
// on the production database:
//   - wfh_sessions_v2 AFTER INSERT  -> late-login detection
//   - wfh_logs_v2     AFTER INSERT  -> tab-switch-to-unauthorized-domain detection
//
// Both push a 0-minute-popup Google Calendar event (via a service account) to the
// configured attendee list, which shows up as an instant phone notification.
//
// Env vars (set with `supabase secrets set` / Management API):
//   HUB_ALERTS_WEBHOOK_SECRET   shared secret the DB trigger sends in x-hub-alerts-secret
//   GOOGLE_CLIENT_EMAIL         service account email
//   GOOGLE_PRIVATE_KEY          service account private key (PEM, \n-escaped)
//   GOOGLE_CALENDAR_ID          calendar to write events to (default: first ALERT_ATTENDEES entry)
//   ALERT_ATTENDEES             comma-separated emails invited to every alert event
//   LATE_THRESHOLD_MINUTES      grace period before a late login alerts (default 5)
//   ALERT_COOLDOWN_MINUTES      per-operator per-alert-type dedup window (default 15)
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY  auto-injected by the Edge Runtime

const HUB_ALERTS_WEBHOOK_SECRET = Deno.env.get("HUB_ALERTS_WEBHOOK_SECRET") ?? "";
const GOOGLE_CLIENT_EMAIL = Deno.env.get("GOOGLE_CLIENT_EMAIL") ?? "";
const GOOGLE_PRIVATE_KEY = (Deno.env.get("GOOGLE_PRIVATE_KEY") ?? "").replace(/\\n/g, "\n");
const ALERT_ATTENDEES = (Deno.env.get("ALERT_ATTENDEES") ?? "")
  .split(",").map((s) => s.trim()).filter(Boolean);
const GOOGLE_CALENDAR_ID = Deno.env.get("GOOGLE_CALENDAR_ID") || ALERT_ATTENDEES[0] || "";
const LATE_THRESHOLD_MINUTES = Number(Deno.env.get("LATE_THRESHOLD_MINUTES") ?? "5");
const ALERT_COOLDOWN_MINUTES = Number(Deno.env.get("ALERT_COOLDOWN_MINUTES") ?? "15");

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

// Domains an operator is expected to be on while working. Anything else
// (YouTube, music/streaming sites, shopping, sports, a mouse-jiggler
// download page, ...) is treated as a "hidden app" tab switch and alerts.
const ALLOWED_DOMAIN_SUFFIXES = [
  "google.com",
  "gstatic.com",
  "live.com",
  "microsoft.com",
  "microsoft", // the .microsoft gTLD itself, e.g. teams.cloud.microsoft
  "microsoftonline.com",
  "sharepoint.com",
  "office.com",
  "impactoutsourcing.co.ke",
  "aifi.com",
  "aifi-hub.vercel.app",
  "aifi-ops-ke.github.io",
  "atlassian.com",
  "atlassian.net",
  "cursor.com",
  "cursor.sh",
  "darkreader.org",
  "fast.com",
];

function isAllowedDomain(domain: string): boolean {
  if (!domain) return true; // blank/new-tab events aren't a real destination
  return ALLOWED_DOMAIN_SUFFIXES.some(
    (suf) => domain === suf || domain.endsWith("." + suf),
  );
}

function titleCaseOpId(opId: string): string {
  return opId
    .split(".")
    .map((w) => (w ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(" ");
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// ── Dedup / cooldown ────────────────────────────────────────────────
async function recentlyAlerted(opId: string, alertType: string): Promise<boolean> {
  const since = new Date(Date.now() - ALERT_COOLDOWN_MINUTES * 60_000).toISOString();
  const url = `${SUPABASE_URL}/rest/v1/hub_alert_log?select=id&op_id=eq.${encodeURIComponent(opId)}&alert_type=eq.${encodeURIComponent(alertType)}&created_at=gt.${encodeURIComponent(since)}&limit=1`;
  const r = await fetch(url, {
    headers: { apikey: SERVICE_ROLE_KEY, Authorization: `Bearer ${SERVICE_ROLE_KEY}` },
  });
  if (!r.ok) return false; // fail open on dedup-check errors, don't swallow real alerts
  const rows = await r.json();
  return Array.isArray(rows) && rows.length > 0;
}

async function recordAlert(opId: string, alertType: string, detail: string): Promise<void> {
  await fetch(`${SUPABASE_URL}/rest/v1/hub_alert_log`, {
    method: "POST",
    headers: {
      apikey: SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      "content-type": "application/json",
      prefer: "return=minimal",
    },
    body: JSON.stringify({ op_id: opId, alert_type: alertType, detail }),
  });
}

// ── Google Calendar (service account, JWT bearer flow) ────────────────
let _cachedToken: { token: string; exp: number } | null = null;

function base64url(input: ArrayBuffer | string): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function getGoogleAccessToken(): Promise<string> {
  if (_cachedToken && _cachedToken.exp > Date.now() + 60_000) return _cachedToken.token;
  if (!GOOGLE_CLIENT_EMAIL || !GOOGLE_PRIVATE_KEY) {
    throw new Error("Google service account not configured (GOOGLE_CLIENT_EMAIL / GOOGLE_PRIVATE_KEY missing)");
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: GOOGLE_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/calendar.events",
    aud: "https://oauth2.googleapis.com/token",
    iat: nowSec,
    exp: nowSec + 3600,
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(GOOGLE_PRIVATE_KEY),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(signingInput),
  );
  const jwt = `${signingInput}.${base64url(signature)}`;

  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(`Google token exchange failed: ${r.status} ${JSON.stringify(data)}`);

  _cachedToken = { token: data.access_token, exp: Date.now() + data.expires_in * 1000 };
  return data.access_token;
}

async function pushCalendarAlert(summary: string, description: string): Promise<void> {
  if (!GOOGLE_CALENDAR_ID || ALERT_ATTENDEES.length === 0) {
    throw new Error("Calendar not configured (GOOGLE_CALENDAR_ID / ALERT_ATTENDEES missing)");
  }
  const token = await getGoogleAccessToken();
  const start = new Date();
  const end = new Date(start.getTime() + 60_000);

  const r = await fetch(
    `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(GOOGLE_CALENDAR_ID)}/events?sendUpdates=all`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        summary,
        description,
        start: { dateTime: start.toISOString() },
        end: { dateTime: end.toISOString() },
        attendees: ALERT_ATTENDEES.map((email) => ({ email })),
        reminders: { useDefault: false, overrides: [{ method: "popup", minutes: 0 }] },
      }),
    },
  );
  const data = await r.json();
  if (!r.ok) throw new Error(`Calendar insert failed: ${r.status} ${JSON.stringify(data)}`);
}

// ── Late-login detection (wfh_sessions_v2) ─────────────────────────────
function parseShiftStartNairobiMinutes(shift: unknown): number | null {
  if (typeof shift !== "string") return null;
  const m = shift.trim().match(/^(\d{2})(\d{2})$/);
  if (!m) return null;
  const hh = Number(m[1]), mm = Number(m[2]);
  if (hh > 23 || mm > 59) return null;
  return ((hh * 60 + mm) + 180) % 1440; // shift is UTC; Nairobi = UTC+3
}

function minutesOfDay(naiveTimestamp: unknown): number | null {
  if (typeof naiveTimestamp !== "string") return null;
  const m = naiveTimestamp.match(/[T ](\d{2}):(\d{2})/);
  if (!m) return null;
  return Number(m[1]) * 60 + Number(m[2]);
}

async function handleSessionInsert(record: Record<string, unknown>) {
  const opId = String(record.op_id ?? "");
  if (!opId) return;

  const scheduled = parseShiftStartNairobiMinutes(record.shift);
  const actual = minutesOfDay(record.check_in);
  if (scheduled === null || actual === null) return; // no valid shift entered, can't judge lateness

  let lateBy = actual - scheduled;
  if (lateBy > 720) lateBy -= 1440;
  if (lateBy < -720) lateBy += 1440;

  if (lateBy < LATE_THRESHOLD_MINUTES) return;

  if (await recentlyAlerted(opId, "late_login")) return;
  await recordAlert(opId, "late_login", `${lateBy} min late`);

  const name = titleCaseOpId(opId);
  await pushCalendarAlert(
    `🔴 Late Login — ${name} (${lateBy} min late)`,
    `${name} (${opId}) checked in ${lateBy} minute(s) after their scheduled shift start.\n` +
      `Scheduled (shift field, UTC): ${record.shift}\nChecked in at (Nairobi): ${record.check_in}\nDate: ${record.date}`,
  );
}

// ── Tab-switch-to-unauthorized-domain detection (wfh_logs_v2) ─────────
function extractSwitchedDomain(notes: string): string | null {
  const m = notes.match(/^Switched to:\s*([^\s(]*)/i);
  return m ? m[1] : null;
}

async function handleLogInsert(record: Record<string, unknown>) {
  if (record.log_type !== "tab_switch") return;
  const notes = String(record.notes ?? "");
  const opId = String(record.op_id ?? "");
  if (!opId) return;

  const domain = extractSwitchedDomain(notes);
  if (domain === null) return; // not a "Switched to:" row (e.g. "Tab hidden", "Away alert") — out of scope
  if (isAllowedDomain(domain)) return;

  if (await recentlyAlerted(opId, "tab_switch")) return;
  await recordAlert(opId, "tab_switch", domain);

  const name = titleCaseOpId(opId);
  await pushCalendarAlert(
    `🚩 Unauthorized Tab — ${name} → ${domain}`,
    `${name} (${opId}) switched to an unrecognized site/app while checked in.\n` +
      `Destination: ${domain}\nRaw log: ${notes}\nLogged at (Nairobi): ${record.logged_at}`,
  );
}

// ── HTTP entrypoint ─────────────────────────────────────────────────
Deno.serve(async (req) => {
  if (req.method === "GET") return json(200, { ok: true });
  if (req.method !== "POST") return json(405, { error: "method not allowed" });

  if (!HUB_ALERTS_WEBHOOK_SECRET || req.headers.get("x-hub-alerts-secret") !== HUB_ALERTS_WEBHOOK_SECRET) {
    return json(401, { error: "unauthorized" });
  }

  let payload: { table?: string; type?: string; record?: Record<string, unknown> };
  try {
    payload = await req.json();
  } catch {
    return json(400, { error: "invalid json" });
  }

  const { table, record } = payload;
  if (!table || !record) return json(400, { error: "missing table/record" });

  try {
    if (table === "wfh_sessions_v2") {
      await handleSessionInsert(record);
    } else if (table === "wfh_logs_v2") {
      await handleLogInsert(record);
    }
    return json(200, { ok: true });
  } catch (e) {
    console.error("hub-alerts error:", e);
    return json(500, { error: String(e) });
  }
});
