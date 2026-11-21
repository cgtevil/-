var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Streamer-Pass"
    };
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }
    const json = /* @__PURE__ */ __name((data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders }
    }), "json");
    try {
      if (url.pathname === "/api/donations" && request.method === "POST") {
        const body = await request.json();
        const donorName = String(body.donor_name || "\u062F\u0627\u0639\u0645 \u0645\u062C\u0647\u0648\u0644").trim().slice(0, 40);
        const network = body.network === "almadar" ? "almadar" : "libyana";
        const amount = Number(body.amount);
        const message = String(body.message || "\u062F\u0639\u0645 \u0645\u0628\u0627\u0634\u0631 \u0644\u0644\u0628\u062B!").trim().slice(0, 120);
        const alertVideoUrl = String(body.alert_video_url || "").trim();
        const alertUid = String(body.alert_uid || body.id || `alert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
        const createdAt = (/* @__PURE__ */ new Date()).toISOString();
        if (!Number.isFinite(amount) || amount <= 0) {
          return json({ ok: false, error: "\u0627\u0644\u0645\u0628\u0644\u063A \u063A\u064A\u0631 \u0635\u062D\u064A\u062D" }, 400);
        }
        await env.DB.prepare(
          `INSERT INTO donation_requests
            (alert_uid, streamer_username, donor_name, network, amount, message, alert_video_url, created_at, review_status, alert_notified)
           VALUES (?1, 'cgtevil', ?2, ?3, ?4, ?5, ?6, ?7, 'approved', 1)`
        ).bind(alertUid, donorName, network, amount, message, alertVideoUrl, createdAt).run();
        const createdItem = {
          alert_uid: alertUid,
          streamer_username: "cgtevil",
          donor_name: donorName,
          network,
          amount,
          message,
          alert_video_url: alertVideoUrl,
          created_at: createdAt,
          review_status: "approved",
          alert_notified: 1
        };
        return json({
          ok: true,
          item: createdItem,
          record: createdItem
        });
      }
      if (url.pathname === "/api/donations" && request.method === "GET") {
        const statusFilter = url.searchParams.get("status");
        let rows;
        if (statusFilter && ["pending", "approved", "rejected"].includes(statusFilter)) {
          rows = await env.DB.prepare(
            `SELECT * FROM donation_requests WHERE review_status = ?1 ORDER BY id DESC LIMIT 50`
          ).bind(statusFilter).all();
        } else {
          rows = await env.DB.prepare(
            `SELECT * FROM donation_requests ORDER BY id DESC LIMIT 50`
          ).all();
        }
        return json({ ok: true, items: rows.results || [] });
      }
      const approveMatch = url.pathname.match(/^\/api\/donations\/([^/]+)\/approve$/);
      if (approveMatch && request.method === "POST") {
        const targetId = approveMatch[1];
        const updated = await env.DB.prepare(
          `UPDATE donation_requests
           SET review_status = 'approved',
               alert_notified = 1
           WHERE alert_uid = ?1 OR CAST(id AS TEXT) = ?1
           RETURNING *`
        ).bind(targetId).first();
        if (!updated) {
          return json({ ok: false, error: "\u0627\u0644\u0637\u0644\u0628 \u063A\u064A\u0631 \u0645\u0648\u062C\u0648\u062F" }, 404);
        }
        return json({ ok: true, item: updated });
      }
      const rejectMatch = url.pathname.match(/^\/api\/donations\/([^/]+)\/reject$/);
      if (rejectMatch && request.method === "POST") {
        const targetId = rejectMatch[1];
        const updated = await env.DB.prepare(
          `UPDATE donation_requests
           SET review_status = 'rejected',
               alert_notified = 0
           WHERE alert_uid = ?1 OR CAST(id AS TEXT) = ?1
           RETURNING *`
        ).bind(targetId).first();
        if (!updated) {
          return json({ ok: false, error: "\u0627\u0644\u0637\u0644\u0628 \u063A\u064A\u0631 \u0645\u0648\u062C\u0648\u062F" }, 404);
        }
        return json({ ok: true, item: updated });
      }
      if (url.pathname === "/api/alerts/latest" && request.method === "GET") {
        const pendingAlert = await env.DB.prepare(
          `SELECT * FROM donation_requests
           WHERE review_status = 'approved' AND alert_notified = 1
           ORDER BY id DESC LIMIT 1`
        ).first();
        return json({ ok: true, alert: pendingAlert || null });
      }
      return json({ ok: false, error: "Not Found" }, 404);
    } catch (err) {
      return json({ ok: false, error: err.message || "Database error" }, 500);
    }
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
