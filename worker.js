const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

const DEFAULT_USER = "cgtevil";
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7;

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
  const bytes = typeof input === "string"
    ? new TextEncoder().encode(input)
    : input;
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function signToken(payload, secret) {
  const payloadB64 = toBase64Url(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payloadB64)
  );
  return `${payloadB64}.${toBase64Url(new Uint8Array(sig))}`;
}

async function verifyToken(token, secret) {
  if (!token || typeof token !== "string" || !secret) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;

  try {
    const [payloadB64, sigB64] = parts;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      fromBase64Url(sigB64),
      new TextEncoder().encode(payloadB64)
    );
    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64Url(payloadB64))
    );

    if (!payload.exp || Number(payload.exp) < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function getExpectedUser(env) {
  return String(env.STREAMER_USERNAME || DEFAULT_USER).trim();
}

function getExpectedPass(env) {
  return typeof env.STREAMER_PASSWORD === "string"
    ? env.STREAMER_PASSWORD
    : "";
}

function getJwtSecret(env) {
  return typeof env.AUTH_SECRET === "string"
    ? env.AUTH_SECRET
    : "";
}

async function isAuthorized(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return false;

  const payload = await verifyToken(
    authHeader.slice(7).trim(),
    getJwtSecret(env)
  );

  return Boolean(
    payload &&
    payload.sub === getExpectedUser(env) &&
    payload.role === "streamer"
  );
}

function normalizeApiPath(rawPathname) {
  const clean = (rawPathname || "/").replace(/\/+$/, "") || "/";
  const apiIdx = clean.indexOf("/api/");
  if (apiIdx !== -1) return clean.slice(apiIdx);
  if (clean.endsWith("/api")) return "/api";
  return clean;
}

async function ensureSchema(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS donations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_uid TEXT UNIQUE NOT NULL,
      streamer_username TEXT DEFAULT 'cgtevil',
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
      created_at TEXT NOT NULL,
      reviewed_at TEXT DEFAULT ''
    )
  `).run();

  const info = await db.prepare("PRAGMA table_info(donations)").all();
  const existingCols = new Set(
    (info.results || []).map(
      (col) => String(col.name || "").toLowerCase()
    )
  );

  const migrations = [
    ["streamer_username", "ALTER TABLE donations ADD COLUMN streamer_username TEXT DEFAULT 'cgtevil'"],
    ["device_id", "ALTER TABLE donations ADD COLUMN device_id TEXT DEFAULT ''"],
    ["tracking_code", "ALTER TABLE donations ADD COLUMN tracking_code TEXT DEFAULT ''"],
    ["sender_last_digits", "ALTER TABLE donations ADD COLUMN sender_last_digits TEXT DEFAULT ''"],
    ["copied_code", "ALTER TABLE donations ADD COLUMN copied_code INTEGER DEFAULT 0"],
    ["elapsed_seconds", "ALTER TABLE donations ADD COLUMN elapsed_seconds INTEGER DEFAULT 0"],
    ["video_url", "ALTER TABLE donations ADD COLUMN video_url TEXT DEFAULT ''"],
    ["youtube_video_id", "ALTER TABLE donations ADD COLUMN youtube_video_id TEXT DEFAULT ''"],
    ["review_status", "ALTER TABLE donations ADD COLUMN review_status TEXT DEFAULT 'pending'"],
    ["alert_notified", "ALTER TABLE donations ADD COLUMN alert_notified INTEGER DEFAULT 0"],
    ["reviewed_at", "ALTER TABLE donations ADD COLUMN reviewed_at TEXT DEFAULT ''"],
  ];

  for (const [colName, sql] of migrations) {
    if (!existingCols.has(colName)) {
      await db.prepare(sql).run();
    }
  }

  await db.prepare(
    "CREATE INDEX IF NOT EXISTS idx_donations_status_id ON donations (review_status, id)"
  ).run();

  await db.prepare(
    "CREATE INDEX IF NOT EXISTS idx_donations_alert_notified ON donations (alert_notified, review_status, id)"
  ).run();
}

function normalizeRow(row) {
  if (!row) return null;

  return {
    id: row.id,
    alert_uid: row.alert_uid,
    streamer_username: row.streamer_username || DEFAULT_USER,
    device_id: row.device_id || "",
    donor_name: row.donor_name,
    amount: Number(row.amount) || 0,
    message: row.message || "",
    tracking_code: row.tracking_code || "",
    sender_last_digits: row.sender_last_digits || "",
    copied_code: Number(row.copied_code) === 1 ? 1 : 0,
    elapsed_seconds: Number(row.elapsed_seconds) || 0,
    network: row.network === "almadar" ? "almadar" : "libyana",
    video_url: row.video_url || "",
    youtube_video_id: row.youtube_video_id || "",
    review_status: row.review_status || "pending",
    alert_notified: Number(row.alert_notified) || 0,
    created_at: row.created_at,
    reviewed_at: row.reviewed_at || "",
  };
}

function safeAlertRow(row) {
  return {
    id: Number(row.id) || 0,
    alert_uid: String(row.alert_uid || ""),
    donor_name: String(row.donor_name || "داعم"),
    amount: Number(row.amount) || 0,
    message: String(row.message || ""),
    network: row.network === "almadar" ? "almadar" : "libyana",
    created_at: row.created_at || "",
    review_status: "approved",
  };
}

function validateNetworkAndAmount(network, amount) {
  const net = network === "almadar" ? "almadar" : "libyana";
  const num = Number(amount);

  if (!Number.isInteger(num)) {
    return { ok: false, error: "المبلغ يجب أن يكون رقماً صحيحاً" };
  }

  if (net === "libyana" && (num < 3 || num > 50)) {
    return { ok: false, error: "حدود ليبيانا من 3 إلى 50 د.ل" };
  }

  if (net === "almadar" && (num < 3 || num > 20)) {
    return { ok: false, error: "حدود المدار من 3 إلى 20 د.ل" };
  }

  return { ok: true, net, amount: num };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS,
      });
    }

    const db = env.DB;

    if (!db) {
      return jsonResponse({
        ok: false,
        error: "قاعدة بيانات D1 غير مربوطة بالمتغير DB",
      }, 500);
    }

    try {
      await ensureSchema(db);

      const url = new URL(request.url);
      const path = normalizeApiPath(url.pathname);
      const method = request.method.toUpperCase();

      if (
        (path === "/" || path === "/api/health") &&
        method === "GET"
      ) {
        return jsonResponse({
          ok: true,
          service: "cgtevil-donations-api",
          status: "ready",
        });
      }

      // تسجيل دخول الستريمر
      if (path === "/api/auth/login" && method === "POST") {
        const expectedPass = getExpectedPass(env);
        const authSecret = getJwtSecret(env);

        if (!expectedPass || !authSecret) {
          return jsonResponse({
            ok: false,
            error: "إعدادات الدخول السرية غير مكتملة في Cloudflare",
          }, 500);
        }

        const body = await request.json().catch(() => ({}));
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (
          username !== getExpectedUser(env) ||
          password !== expectedPass
        ) {
          return jsonResponse({
            ok: false,
            error: "اسم المستخدم أو كلمة المرور غير صحيحة",
          }, 401);
        }

        const nowSec = Math.floor(Date.now() / 1000);

        const token = await signToken({
          sub: username,
          role: "streamer",
          iat: nowSec,
          exp: nowSec + TOKEN_TTL_SECONDS,
        }, authSecret);

        return jsonResponse({
          ok: true,
          token,
          username,
          expires_in: TOKEN_TTL_SECONDS,
        });
      }

      // قائمة أبرز 3 داعمين - بيانات عامة مجمعة فقط
      if (
        path === "/api/public/top-supporters" &&
        method === "GET"
      ) {
        const { results } = await db.prepare(`
          SELECT donor_name, SUM(amount) AS amount
          FROM donations
          WHERE review_status = 'approved'
          GROUP BY donor_name
          ORDER BY amount DESC, donor_name ASC
          LIMIT 3
        `).all();

        const items = (results || []).map((row) => ({
          donor_name: String(row.donor_name || "داعم"),
          amount: Number(row.amount) || 0,
          review_status: "approved",
        }));

        return jsonResponse({ ok: true, items });
      }

      // عرض الطلبات الخاصة بالستريمر فقط
      if (path === "/api/donations" && method === "GET") {
        if (!(await isAuthorized(request, env))) {
          return jsonResponse({
            ok: false,
            error: "يلزم تسجيل دخول الستريمر لعرض الطلبات",
          }, 401);
        }

        const { results } = await db.prepare(
          "SELECT * FROM donations ORDER BY id DESC LIMIT 200"
        ).all();

        return jsonResponse({
          ok: true,
          items: (results || []).map(normalizeRow),
        });
      }

      // استقبال طلب دعم جديد
      if (path === "/api/donations" && method === "POST") {
        const body = await request.json().catch(() => ({}));

        const donorName = String(body.donor_name || "")
          .trim().slice(0, 40);

        const message = String(body.message || "دعم مباشر للبث!")
          .trim().slice(0, 140);

        const trackingCode = String(body.tracking_code || "")
          .trim().slice(0, 20);

        const senderDigits = String(body.sender_last_digits || "")
          .replace(/[^0-9]/g, "")
          .slice(0, 4);

        const copiedCode =
          body.copied_code === true ||
          Number(body.copied_code) === 1 ? 1 : 0;

        const elapsedSeconds = Math.max(
          0,
          Math.min(3600, Number(body.elapsed_seconds) || 0)
        );

        const deviceId = String(body.device_id || "")
          .trim().slice(0, 80);

        const videoUrl = String(body.video_url || "")
          .trim().slice(0, 300);

        const youtubeVideoId = String(body.youtube_video_id || "")
          .trim().slice(0, 30);

        if (!donorName) {
          return jsonResponse({
            ok: false,
            error: "اسم الداعم مطلوب",
          }, 400);
        }

        const netCheck = validateNetworkAndAmount(
          body.network,
          body.amount
        );

        if (!netCheck.ok) {
          return jsonResponse({
            ok: false,
            error: netCheck.error,
          }, 400);
        }

        const alertUid =
          String(body.alert_uid || "").trim().slice(0, 80) ||
          `alert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

        const createdAt = body.created_at
          ? String(body.created_at)
          : new Date().toISOString();

        await db.prepare(`
          INSERT INTO donations (
            alert_uid, streamer_username, device_id, donor_name, amount,
            message, tracking_code, sender_last_digits, copied_code,
            elapsed_seconds, network, video_url, youtube_video_id,
            review_status, alert_notified, created_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?)
        `).bind(
          alertUid,
          getExpectedUser(env),
          deviceId,
          donorName,
          netCheck.amount,
          message,
          trackingCode,
          senderDigits,
          copiedCode,
          elapsedSeconds,
          netCheck.net,
          videoUrl,
          youtubeVideoId,
          createdAt
        ).run();

        const createdRow = await db.prepare(
          "SELECT * FROM donations WHERE alert_uid = ?"
        ).bind(alertUid).first();

        return jsonResponse({
          ok: true,
          item: normalizeRow(createdRow),
        }, 201);
      }

      // قبول أو رفض طلب دعم
      const reviewMatch = path.match(
        /^\/api\/donations\/([^/]+)\/(approve|reject)$/
      );

      if (reviewMatch && method === "POST") {
        if (!(await isAuthorized(request, env))) {
          return jsonResponse({
            ok: false,
            error: "غير مصرح لك بتنفيذ هذا الإجراء",
          }, 401);
        }

        const identifier = decodeURIComponent(reviewMatch[1]).trim();

        const nextStatus = reviewMatch[2] === "approve"
          ? "approved"
          : "rejected";

        const reviewedAt = new Date().toISOString();

        const existing = await db.prepare(
          "SELECT * FROM donations WHERE alert_uid = ? OR CAST(id AS TEXT) = ?"
        ).bind(identifier, identifier).first();

        if (!existing) {
          return jsonResponse({
            ok: false,
            error: "الطلب غير موجود",
          }, 404);
        }

        await db.prepare(`
          UPDATE donations
          SET review_status = ?,
              reviewed_at = ?,
              alert_notified = CASE
                WHEN ? = 'approved' THEN 0
                ELSE alert_notified
              END
          WHERE id = ?
        `).bind(
          nextStatus,
          reviewedAt,
          nextStatus,
          existing.id
        ).run();

        const updated = await db.prepare(
          "SELECT * FROM donations WHERE id = ?"
        ).bind(existing.id).first();

        return jsonResponse({
          ok: true,
          item: normalizeRow(updated),
        });
      }

      // جلب التنبيهات المقبولة دون وضع علامة الإرسال قبل استلامها
      if (
        (
          path === "/api/alerts/pending-dispatch" ||
          path === "/api/alerts/recent-approved"
        ) &&
        method === "GET"
      ) {
        const { results } = await db.prepare(`
          SELECT id, alert_uid, donor_name, amount, message, network, created_at
          FROM donations
          WHERE review_status = 'approved'
            AND alert_notified = 0
          ORDER BY id ASC
          LIMIT 20
        `).all();

        return jsonResponse({
          ok: true,
          items: (results || []).map(safeAlertRow),
        });
      }

      // تأكيد استلام التنبيه بعد إضافته إلى قائمة العرض
      if (path === "/api/alerts/ack" && method === "POST") {
        const body = await request.json().catch(() => ({}));

        const ids = Array.isArray(body.ids)
          ? [...new Set(
              body.ids
                .map((x) => Number(x))
                .filter((x) => Number.isInteger(x) && x > 0)
            )].slice(0, 20)
          : [];

        if (!ids.length) {
          return jsonResponse({
            ok: true,
            acknowledged: 0,
          });
        }

        const placeholders = ids.map(() => "?").join(", ");

        const result = await db.prepare(`
          UPDATE donations
          SET alert_notified = 1
          WHERE review_status = 'approved'
            AND alert_notified = 0
            AND id IN (${placeholders})
        `).bind(...ids).run();

        return jsonResponse({
          ok: true,
          acknowledged: Number(result.meta?.changes) || 0,
        });
      }

      // حذف طلب محدد
      const deleteMatch = path.match(/^\/api\/donations\/([^/]+)$/);

      if (deleteMatch && method === "DELETE") {
        if (!(await isAuthorized(request, env))) {
          return jsonResponse({
            ok: false,
            error: "غير مصرح لك بالحذف",
          }, 401);
        }

        const identifier = decodeURIComponent(deleteMatch[1]).trim();

        await db.prepare(
          "DELETE FROM donations WHERE alert_uid = ? OR CAST(id AS TEXT) = ?"
        ).bind(identifier, identifier).run();

        return jsonResponse({
          ok: true,
          deleted: identifier,
        });
      }

      // مسح الطلبات
      if (path === "/api/donations/clear" && method === "POST") {
        if (!(await isAuthorized(request, env))) {
          return jsonResponse({
            ok: false,
            error: "غير مصرح لك بالمسح",
          }, 401);
        }

        const body = await request.json().catch(() => ({}));

        const uids = Array.isArray(body.alert_uids)
          ? body.alert_uids
              .map((x) => String(x || "").trim())
              .filter(Boolean)
          : [];

        if (!uids.length) {
          await db.prepare("DELETE FROM donations").run();

          return jsonResponse({
            ok: true,
            cleared: "all",
          });
        }

        const placeholders = uids.map(() => "?").join(", ");

        await db.prepare(`
          DELETE FROM donations
          WHERE alert_uid IN (${placeholders})
             OR CAST(id AS TEXT) IN (${placeholders})
        `).bind(...uids, ...uids).run();

        return jsonResponse({
          ok: true,
          cleared: uids.length,
        });
      }

      return jsonResponse({
        ok: false,
        error: "Not Found",
      }, 404);

    } catch (err) {
      return jsonResponse({
        ok: false,
        error: err && err.message
          ? err.message
          : "خطأ داخلي في الخادم",
      }, 500);
    }
  },
};
