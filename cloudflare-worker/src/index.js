/**
 * CGTEVIL phone ownership OTP API.
 * Phone verification only: no payments, balance transfers, USSD or deductions.
 */
const json = (data, status = 200, origin = "*") => new Response(JSON.stringify(data), {
  status, headers: {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "Content-Type",
    "vary": "Origin", "cache-control": "no-store"
  }
});
function validPhone(value) {
  return typeof value === "string" && /^(091|093|092|094)\d{7}$/.test(value);
}
function normalizePhone(local) { return "218" + local.slice(1); }
async function otpHash(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const digest = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, "0")).join("");
}
function allowedOrigin(env) { return env.ALLOWED_ORIGIN || "https://cgtevil.github.io"; }

export default {
  async fetch(request, env) {
    const origin = allowedOrigin(env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "Content-Type", "vary": "Origin"
    }});
    const url = new URL(request.url);
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405, origin);
    if (request.headers.get("Origin") && request.headers.get("Origin") !== origin) {
      return json({ error: "Origin not allowed" }, 403, origin);
    }
    let body;
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400, origin); }
    const phone = body?.phone;
    if (!validPhone(phone)) return json({ error: "أدخل رقم ليبي صحيحاً." }, 400, origin);
    const store = env.OTP_STORE.get(env.OTP_STORE.idFromName(phone));

    if (url.pathname === "/api/send-otp") {
      if (!env.RESALA_API_KEY || !env.RESALA_SERVICE_NAME) {
        return json({ error: "إعدادات Resala غير مكتملة على الخادم." }, 503, origin);
      }
      const reservation = await store.fetch("https://otp-store/reserve", { method: "POST" });
      if (!reservation.ok) return json({ error: "انتظر دقيقة قبل طلب رمز جديد." }, 429, origin);

      // Resala expects service_name, len, and test as URL query parameters.
      const params = new URLSearchParams({ service_name: env.RESALA_SERVICE_NAME, len: "6" });
      const testFlag = env.RESALA_TEST === "true" ? "&test" : "";
      const sms = await fetch(`https://dev.resala.ly/api/v1/pins?${params.toString()}${testFlag}`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${env.RESALA_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({ phone: normalizePhone(phone) })
      });
      const payload = await sms.json().catch(() => ({}));
      const pin = payload?.pin ?? payload?.data?.pin;
      if (!sms.ok || !pin) return json({ error: "فشل إرسال SMS. راجع إعدادات Resala." }, 502, origin);

      const saved = await store.fetch("https://otp-store/save", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ pinHash: await otpHash(String(pin), env.RESALA_API_KEY) })
      });
      if (!saved.ok) return json({ error: "تعذر حفظ الرمز بأمان." }, 500, origin);
      return json({ sent: true, expiresIn: 300, testMode: env.RESALA_TEST === "true" }, 200, origin);
    }

    if (url.pathname === "/api/verify-otp") {
      if (!env.RESALA_API_KEY) return json({ error: "إعدادات الخادم غير مكتملة." }, 503, origin);
      const code = body?.code;
      if (typeof code !== "string" || !/^\d{6}$/.test(code)) {
        return json({ error: "الرمز يجب أن يتكون من 6 أرقام." }, 400, origin);
      }
      const checked = await store.fetch("https://otp-store/verify", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ codeHash: await otpHash(code, env.RESALA_API_KEY) })
      });
      const result = await checked.json().catch(() => ({}));
      if (!checked.ok || result.verified !== true) {
        return json({ verified: false, error: "رمز غير صحيح أو منتهي الصلاحية." }, 400, origin);
      }
      return json({ verified: true, purpose: "phone-ownership-only" }, 200, origin);
    }
    return json({ error: "Not found" }, 404, origin);
  }
};

export class OtpStore {
  constructor(state) { this.state = state; }
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === "/reserve") {
      const last = await this.state.storage.get("lastSentAt") || 0;
      if (Date.now() - last < 60000) return new Response("rate limited", { status: 429 });
      await this.state.storage.put("lastSentAt", Date.now());
      return new Response("ok");
    }
    if (path === "/save") {
      const { pinHash } = await request.json();
      await this.state.storage.put("pinHash", pinHash, { expirationTtl: 300 });
      await this.state.storage.put("attempts", 0, { expirationTtl: 300 });
      return new Response("ok");
    }
    if (path === "/verify") {
      const { codeHash } = await request.json();
      const expected = await this.state.storage.get("pinHash");
      const attempts = await this.state.storage.get("attempts") || 0;
      if (!expected || attempts >= 5) return Response.json({ verified: false }, { status: 400 });
      if (codeHash !== expected) {
        await this.state.storage.put("attempts", attempts + 1, { expirationTtl: 300 });
        return Response.json({ verified: false }, { status: 400 });
      }
      await this.state.storage.delete("pinHash");
      await this.state.storage.delete("attempts");
      return Response.json({ verified: true });
    }
    return new Response("not found", { status: 404 });
  }
}
