const DEFAULT_USER = "cgt_evil";
const DEFAULT_PASS = "cgt_evil01";
const DEFAULT_SECRET = "cgtevil-worker-secret-2026";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...CORS_HEADERS,
    },
  });
}

function toBase64Url(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function signToken(payloadObj, secret) {
  const headerB64 = toBase64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payloadB64 = toBase64Url(JSON.stringify(payloadObj));
  const data = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuffer = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const sigB64 = toBase64Url(new Uint8Array(sigBuffer));
  return `${data}.${sigB64}`;
}

async function verifyToken(token, secret, expectedSub = DEFAULT_USER) {
  try {
    if (!token || typeof token !== "string") return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, sigB64] = parts;
    const data = `${headerB64}.${payloadB64}`;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const normalizedSig =
      sigB64.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (sigB64.length % 4)) % 4);
    const sigBinary = atob(normalizedSig);
    const sigBytes = new Uint8Array(sigBinary.length);
    for (let i = 0; i < sigBinary.length; i++) {
      sigBytes[i] = sigBinary.charCodeAt(i);
    }

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      new TextEncoder().encode(data)
    );
    if (!valid) return null;

    const normalizedPayload =
      payloadB64.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (payloadB64.length % 4)) % 4);
    const payload = JSON.parse(atob(normalizedPayload));
    if (
      !payload ||
      payload.sub !== expectedSub ||
      Number(payload.exp) <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }
    return payload;
  } catch (e) {
    return null;
  }
}

async function isAuthorizedStreamer(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  const secret = env.JWT_SECRET || DEFAULT_SECRET;
  const expectedUser = String(env.STREAMER_USER || DEFAULT_USER).trim();
  const payload = await verifyToken(token, secret, expectedUser);
  return Boolean(payload);
}

async function ensureSchema(db) {
  await db
    .prepare(
      `
    CREATE TABLE IF NOT EXISTS donations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_uid TEXT UNIQUE NOT NULL,
      streamer_username TEXT DEFAULT 'cgt_evil',
      device_id TEXT DEFAULT '',
      donor_name TEXT NOT NULL,
      amount INTEGER NOT NULL,
      message TEXT DEFAULT '',
      tracking_code TEXT DEFAULT '',
      sender_last_digits TEXT DEFAULT '',
      copied_code INTEGER DEFAULT 0,
      elapsed_seconds INTEGER DEFAULT 0,
      network TEXT DEFAULT 'libyana',
      video_url TEXT DEFAULT '',
      youtube_video_id TEXT DEFAULT '',
      review_status TEXT DEFAULT 'pending',
      alert_notified INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    )
  `
    )
    .run();
}

function mapDonationRow(row) {
  return {
    id: row.id,
    alert_uid: row.alert_uid,
    streamer_username: row.streamer_username || DEFAULT_USER,
    device_id: row.device_id || "",
    donor_name: row.donor_name || "داعم",
    amount: Number(row.amount) || 0,
    message: row.message || "",
    tracking_code: row.tracking_code || "",
    sender_last_digits: row.sender_last_digits || "",
    copied_code: Number(row.copied_code) || 0,
    elapsed_seconds: Number(row.elapsed_seconds) || 0,
    network: row.network || "libyana",
    video_url: row.video_url || "",
    youtube_video_id: row.youtube_video_id || "",
    review_status: row.review_status || "pending",
    alert_notified: Number(row.alert_notified) || 0,
    created_at: row.created_at,
  };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method.toUpperCase();

    try {
      // 1. تسجيل دخول الستريمر -> يوقّع JWT بصيغة header.payload.signature
      if (path === "/api/auth/login" && method === "POST") {
        const body = await request.json().catch(() => ({}));
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        const expectedUser = String(env.STREAMER_USER || DEFAULT_USER).trim();
        const expectedPass = String(env.STREAMER_PASS || DEFAULT_PASS);

        if (username !== expectedUser || password !== expectedPass) {
          return jsonResponse(
            { ok: false, error: "اسم المستخدم أو رمز الدخول غير صحيح" },
            401
          );
        }

        const nowSec = Math.floor(Date.now() / 1000);
        const secret = env.JWT_SECRET || DEFAULT_SECRET;
        const token = await signToken(
          {
            sub: expectedUser,
            role: "streamer",
            iat: nowSec,
            exp: nowSec + 60 * 60 * 24 * 7,
          },
          secret
        );

        return jsonResponse({ ok: true, token, username: expectedUser });
      }

      if (!env.DB) {
        return jsonResponse(
          { ok: false, error: "قاعدة البيانات D1 (Binding: DB) غير مرتبطة بالـ Worker" },
          500
        );
      }
      await ensureSchema(env.DB);

      // 2. إرسال طلب دعم جديد من الداعم
      if (path === "/api/donations" && method === "POST") {
        const body = await request.json().catch(() => ({}));
        const donorName = String(body.donor_name || "").trim().slice(0, 40);
        const amount = Number(body.amount);
        const network = body.network === "almadar" ? "almadar" : "libyana";
        const maxAmount = network === "almadar" ? 20 : 50;

        if (!donorName) {
          return jsonResponse({ ok: false, error: "اسم الداعم مطلوب" }, 400);
        }
        if (!Number.isInteger(amount) || amount < 3 || amount > maxAmount) {
          return jsonResponse(
            { ok: false, error: `المبلغ يجب أن يكون بين 3 و ${maxAmount} د.ل` },
            400
          );
        }

        const alertUid = String(
          body.alert_uid ||
            body.id ||
            `alert_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`
        ).trim();
        const message = String(body.message || "دعم مباشر للبث!")
          .trim()
          .slice(0, 140);
        const trackingCode = String(body.tracking_code || "").trim().slice(0, 20);
        const senderLastDigits = String(body.sender_last_digits || "")
          .replace(/\D/g, "")
          .slice(0, 4);
        const copiedCode = body.copied_code ? 1 : 0;
        const elapsedSeconds = Math.max(
          0,
          Math.min(3600, Number(body.elapsed_seconds) || 0)
        );
        const deviceId = String(body.device_id || "").trim().slice(0, 80);
        const videoUrl = String(body.video_url || "").trim().slice(0, 300);
        const youtubeVideoId = String(body.youtube_video_id || "")
          .trim()
          .slice(0, 30);
        const createdAt = body.created_at
          ? String(body.created_at)
          : new Date().toISOString();

        await env.DB.prepare(
          `
          INSERT INTO donations (
            alert_uid, streamer_username, device_id, donor_name, amount, message,
            tracking_code, sender_last_digits, copied_code, elapsed_seconds,
            network, video_url, youtube_video_id, review_status, alert_notified, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?)
        `
        )
          .bind(
            alertUid,
            DEFAULT_USER,
            deviceId,
            donorName,
            amount,
            message,
            trackingCode,
            senderLastDigits,
            copiedCode,
            elapsedSeconds,
            network,
            videoUrl,
            youtubeVideoId,
            createdAt
          )
          .run();

        const created = await env.DB.prepare(
          `SELECT * FROM donations WHERE alert_uid = ?`
        )
          .bind(alertUid)
          .first();
        return jsonResponse(
          { ok: true, item: created ? mapDonationRow(created) : null },
          201
        );
      }

      // 3. جلب جميع الطلبات للستريمر
      if (path === "/api/donations" && method === "GET") {
        if (!(await isAuthorizedStreamer(request, env))) {
          return jsonResponse({ ok: false, error: "غير مصرح لك بالوصول" }, 401);
        }
        const rows = await env.DB.prepare(
          `SELECT * FROM donations ORDER BY id DESC LIMIT 200`
        ).all();
        const items = (rows.results || []).map(mapDonationRow);
        return jsonResponse({ ok: true, items });
      }

      // 4. قبول أو رفض طلب دعم
      const reviewMatch = path.match(
        /^\/api\/donations\/([^/]+)\/(approve|reject)$/
      );
      if (reviewMatch && method === "POST") {
        if (!(await isAuthorizedStreamer(request, env))) {
          return jsonResponse({ ok: false, error: "غير مصرح لك بالوصول" }, 401);
        }
        const uid = decodeURIComponent(reviewMatch[1]);
        const nextStatus = reviewMatch[2] === "reject" ? "rejected" : "approved";
        const nextNotified = nextStatus === "approved" ? 1 : 0;

        await env.DB.prepare(
          `
          UPDATE donations
          SET review_status = ?, alert_notified = ?
          WHERE alert_uid = ? OR CAST(id AS TEXT) = ?
        `
        )
          .bind(nextStatus, nextNotified, uid, uid)
          .run();

        const updated = await env.DB.prepare(
          `
          SELECT * FROM donations WHERE alert_uid = ? OR CAST(id AS TEXT) = ? LIMIT 1
        `
        )
          .bind(uid, uid)
          .first();

        if (!updated) {
          return jsonResponse({ ok: false, error: "الطلب غير موجود" }, 404);
        }
        return jsonResponse({ ok: true, item: mapDonationRow(updated) });
      }

      // 5. مسح عدة طلبات دفعة واحدة
      if (path === "/api/donations/clear" && method === "POST") {
        if (!(await isAuthorizedStreamer(request, env))) {
          return jsonResponse({ ok: false, error: "غير مصرح لك بالوصول" }, 401);
        }
        const body = await request.json().catch(() => ({}));
        const uids = Array.isArray(body.alert_uids)
          ? body.alert_uids.filter(Boolean)
          : [];

        if (uids.length > 0) {
          const placeholders = uids.map(() => "?").join(",");
          await env.DB.prepare(
            `DELETE FROM donations WHERE alert_uid IN (${placeholders}) OR CAST(id AS TEXT) IN (${placeholders})`
          )
            .bind(...uids, ...uids)
            .run();
        } else {
          await env.DB.prepare(`DELETE FROM donations`).run();
        }
        return jsonResponse({ ok: true });
      }

      // 6. حذف طلب واحد
      const singleDeleteMatch = path.match(/^\/api\/donations\/([^/]+)$/);
      if (singleDeleteMatch && method === "DELETE") {
        if (!(await isAuthorizedStreamer(request, env))) {
          return jsonResponse({ ok: false, error: "غير مصرح لك بالوصول" }, 401);
        }
        const uid = decodeURIComponent(singleDeleteMatch[1]);
        await env.DB.prepare(
          `DELETE FROM donations WHERE alert_uid = ? OR CAST(id AS TEXT) = ?`
        )
          .bind(uid, uid)
          .run();
        return jsonResponse({ ok: true });
      }

      // 7. جلب التنبيهات المعتمدة بانتظار العرض في رابط البث (?widget=true)
      if (path === "/api/alerts/pending-dispatch" && method === "GET") {
        const rows = await env.DB.prepare(
          `
          SELECT * FROM donations
          WHERE review_status = 'approved' AND alert_notified = 1
          ORDER BY id ASC LIMIT 10
        `
        ).all();
        const items = (rows.results || []).map(mapDonationRow);
        return jsonResponse({ ok: true, items });
      }

      // 8. تأكيد عرض التنبيه في رابط البث
      if (path === "/api/alerts/ack" && method === "POST") {
        const body = await request.json().catch(() => ({}));
        const ids = Array.isArray(body.ids)
          ? body.ids
              .map((x) => Number(x))
              .filter((n) => Number.isInteger(n) && n > 0)
          : [];
        if (ids.length > 0) {
          const placeholders = ids.map(() => "?").join(",");
          await env.DB.prepare(
            `UPDATE donations SET alert_notified = 0 WHERE id IN (${placeholders})`
          )
            .bind(...ids)
            .run();
        }
        return jsonResponse({ ok: true });
      }

      // 9. جلب الداعمين المعتمدين لقائمة أبرز 3 داعمين (?top=true)
      if (path === "/api/public/top-supporters" && method === "GET") {
        const rows = await env.DB.prepare(
          `
          SELECT * FROM donations
          WHERE review_status = 'approved'
          ORDER BY amount DESC, id DESC LIMIT 100
        `
        ).all();
        const items = (rows.results || []).map(mapDonationRow);
        return jsonResponse({ ok: true, items });
      }

      return jsonResponse({ ok: false, error: "المسار غير موجود" }, 404);
    } catch (err) {
      return jsonResponse(
        { ok: false, error: err.message || "خطأ داخلي في الخادم" },
        500
      );
    }
  },
};
