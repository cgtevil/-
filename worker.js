export default {
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

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders }
      });

    try {
      // 1) إرسال طلب دعم جديد من الزائر (حالة المراجعة: pending)
      if (url.pathname === "/api/donations" && request.method === "POST") {
        const body = await request.json();
        const donorName = String(body.donor_name || "داعم مجهول").trim().slice(0, 40);
        const network = body.network === "almadar" ? "almadar" : "libyana";
        const amount = Number(body.amount);
        const message = String(body.message || "دعم مباشر للبث!").trim().slice(0, 120);
        const alertVideoUrl = String(body.alert_video_url || "").trim();
        const alertUid = String(body.id || `alert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
        const createdAt = new Date().toISOString();

        if (!Number.isFinite(amount) || amount <= 0) {
          return json({ ok: false, error: "المبلغ غير صحيح" }, 400);
        }

        await env.DB.prepare(
          `INSERT INTO donation_requests
            (alert_uid, streamer_username, donor_name, network, amount, message, alert_video_url, created_at, review_status, alert_notified)
           VALUES (?1, 'cgtevil', ?2, ?3, ?4, ?5, ?6, ?7, 'pending', 0)`
        )
          .bind(alertUid, donorName, network, amount, message, alertVideoUrl, createdAt)
          .run();

        return json({
          ok: true,
          record: {
            alert_uid: alertUid,
            donor_name: donorName,
            network,
            amount,
            message,
            alert_video_url: alertVideoUrl,
            created_at: createdAt,
            review_status: "pending",
            alert_notified: 0
          }
        });
      }

      // 2) جلب الطلبات للوحة الستريمر
      if (url.pathname === "/api/donations" && request.method === "GET") {
        const statusFilter = url.searchParams.get("status");
        let rows;
        if (statusFilter && ["pending", "approved", "rejected"].includes(statusFilter)) {
          rows = await env.DB.prepare(
            `SELECT * FROM donation_requests WHERE review_status = ?1 ORDER BY id DESC LIMIT 50`
          )
            .bind(statusFilter)
            .all();
        } else {
          rows = await env.DB.prepare(
            `SELECT * FROM donation_requests ORDER BY id DESC LIMIT 50`
          ).all();
        }
        return json({ ok: true, items: rows.results || [] });
      }

      // 3) اعتماد الطلب وإطلاق إشعار البث
      const approveMatch = url.pathname.match(/^\/api\/donations\/([^/]+)\/approve$/);
      if (approveMatch && request.method === "POST") {
        const targetId = approveMatch[1];
        const nowIso = new Date().toISOString();

        const updated = await env.DB.prepare(
          `UPDATE donation_requests
           SET review_status = 'approved',
               reviewed_at = ?1,
               alert_notified = 1,
               alert_notified_at = ?1
           WHERE alert_uid = ?2 OR CAST(id AS TEXT) = ?2
           RETURNING *`
        )
          .bind(nowIso, targetId)
          .first();

        if (!updated) {
          return json({ ok: false, error: "الطلب غير موجود" }, 404);
        }

        return json({ ok: true, item: updated });
      }

      // 4) رفض الطلب
      const rejectMatch = url.pathname.match(/^\/api\/donations\/([^/]+)\/reject$/);
      if (rejectMatch && request.method === "POST") {
        const targetId = rejectMatch[1];
        const nowIso = new Date().toISOString();

        const updated = await env.DB.prepare(
          `UPDATE donation_requests
           SET review_status = 'rejected',
               reviewed_at = ?1,
               alert_notified = 0
           WHERE alert_uid = ?2 OR CAST(id AS TEXT) = ?2
           RETURNING *`
        )
          .bind(nowIso, targetId)
          .first();

        if (!updated) {
          return json({ ok: false, error: "الطلب غير موجود" }, 404);
        }

        return json({ ok: true, item: updated });
      }

      // 5) جلب أحدث إشعار معتمد لم يُعرض بعد على البث
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
