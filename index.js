var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

/* ===============================
GOOGLE SHEETS APPEND
=============================== */

async function appendToSheet(env, row) {

const now = Math.floor(Date.now() / 1000);

const header = { alg: "RS256", typ: "JWT" };

const claim = {
iss: env.GOOGLE_CLIENT_EMAIL,
scope: "https://www.googleapis.com/auth/spreadsheets",
aud: "https://oauth2.googleapis.com/token",
iat: now,
exp: now + 3600
};

const b64 = (obj) =>
btoa(JSON.stringify(obj))
.replace(/\+/g, "-")
.replace(/\//g, "_")
.replace(/=+$/, "");

const unsigned = `${b64(header)}.${b64(claim)}`;

const keyPem = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n");

const keyData = keyPem
.replace("-----BEGIN PRIVATE KEY-----", "")
.replace("-----END PRIVATE KEY-----", "")
.replace(/\n/g, "");

const key = await crypto.subtle.importKey(
"pkcs8",
Uint8Array.from(atob(keyData), c => c.charCodeAt(0)),
{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
false,
["sign"]
);

const signature = await crypto.subtle.sign(
"RSASSA-PKCS1-v1_5",
key,
new TextEncoder().encode(unsigned)
);

const jwt =
unsigned +
"." +
btoa(String.fromCharCode(...new Uint8Array(signature)))
.replace(/\+/g, "-")
.replace(/\//g, "_")
.replace(/=+$/, "");

const tokenRes = await fetch(
"https://oauth2.googleapis.com/token",
{
method: "POST",
headers: { "Content-Type": "application/x-www-form-urlencoded" },
body: new URLSearchParams({
grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
assertion: jwt
})
}
);

const { access_token } = await tokenRes.json();

await fetch(
`https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/${env.GOOGLE_SHEET_NAME}!A2:append?valueInputOption=USER_ENTERED`,
{
method: "POST",
headers: {
Authorization: `Bearer ${access_token}`,
"Content-Type": "application/json"
},
body: JSON.stringify({
values: [row]
})
}
);

}

__name(appendToSheet, "appendToSheet");


/* ===============================
MAIN WORKER
=============================== */

export default {

async fetch(request, env) {

/* ===============================
CORS
=============================== */

if (request.method === "OPTIONS") {
return new Response(null, {
status: 204,
headers: {
"Access-Control-Allow-Origin": "*",
"Access-Control-Allow-Methods": "POST, OPTIONS",
"Access-Control-Allow-Headers": "Content-Type"
}
});
}

if (request.method !== "POST") {
return new Response("Method Not Allowed", { status: 405 });
}

/* ===============================
GET FORM
=============================== */

const form = await request.formData();

/* ===============================
HONEYPOT
=============================== */

if (form.get("_gotcha") || form.get("referral_code")) {
return new Response("Spam blocked", { status: 400 });
}



/* ===============================
REFERER PROTECTION
=============================== */

const referer = request.headers.get("referer") || "";

// allow empty referer (fetch requests)
if (referer && !referer.includes("shorelinerecruitmentgroup.com")) {
  return new Response("OK", { status: 200 });
}

/* ===============================
FORM DATA
=============================== */

const name = form.get("fullName") || "";
const phone = form.get("phone") || "";
const email = form.get("email") || "";
const role = form.get("role") || "";
const message = form.get("message") || "";

/* ===============================
SMS ALERT
=============================== */

const smsBody =
`📈 New Shoreline Recruitment Lead

Name: ${name}
Phone: ${phone}
Email: ${email}
Role Needed: ${role}
Message: ${message}`;

const auth = btoa(
`${env.TWILIO_API_KEY_SID}:${env.TWILIO_API_KEY_SECRET}`
);

await fetch(
`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`,
{
method: "POST",
headers: {
Authorization: `Basic ${auth}`,
"Content-Type": "application/x-www-form-urlencoded"
},
body: new URLSearchParams({
To: "+19139577764",
MessagingServiceSid: env.TWILIO_MESSAGING_SERVICE,
Body: smsBody
})
}
);



/* ===============================
SAVE TO GOOGLE SHEETS
=============================== */

await appendToSheet(env, [

new Date().toLocaleString("en-US", { timeZone: "America/Chicago" }), // Timestamp
name,              // Full Name
phone,             // Phone
email,             // Email
role,              // Role Needed
message,           // How can we help you?
referer,           // Page
request.headers.get("cf-connecting-ip") || "" // IP

]);

/* ===============================
SUCCESS
=============================== */

return new Response("OK", {
status: 200,
headers: {
"Access-Control-Allow-Origin": "*"
}
});

}

};
