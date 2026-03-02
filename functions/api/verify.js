export async function onRequestPost(context) {
    const { request, env } = context;

    try {
        // 1. Get Data
        const data = await request.json();
        const { user_id, bot, botHash, device_fingerprint } = data;

        // Validation
        if (!user_id || !bot || !device_fingerprint) {
            return jsonResponse({ status: "fail", message: "Invalid request data." }, 400);
        }

        // 2. Get IP
        const ip = request.headers.get("CF-Connecting-IP") || "Unknown";

        // 3. Check Ban List
        const banned = await env.DB.prepare(
            "SELECT user_id FROM banned_users WHERE user_id = ?"
        ).bind(user_id).first();

        if (banned) {
            return jsonResponse({ status: "fail", message: "User banned." }, 403);
        }

        // 4. Multi-Account Detection Logic
        
        // Check A: Is this Device already used by another user?
        const deviceCheck = await env.DB.prepare(
            "SELECT user_id FROM fingerprints WHERE fingerprint_hash = ? AND user_id != ?"
        ).bind(device_fingerprint, user_id).first();

        if (deviceCheck) {
            return jsonResponse({ status: "fail", message: "Multiple devices detected (Device mismatch)." }, 403);
        }

        // Check B: Is this User already verified?
        const userCheck = await env.DB.prepare(
            "SELECT id FROM fingerprints WHERE user_id = ? AND bot = ?"
        ).bind(user_id, bot).first();

        if (userCheck) {
            return jsonResponse({ status: "success", message: "Already Verified." });
        }

        // Check C: (Optional) IP Limit - Block if more than 3 accounts from same IP
        const ipCheck = await env.DB.prepare(
            "SELECT COUNT(*) as count FROM fingerprints WHERE ip_address = ?"
        ).bind(ip).first();

        if (ipCheck && ipCheck.count >= 3) {
             return jsonResponse({ status: "fail", message: "Suspicious IP activity detected." }, 403);
        }

        // 5. Insert Verification Record
        await env.DB.prepare(
            "INSERT INTO fingerprints (user_id, bot, fingerprint_hash, ip_address) VALUES (?, ?, ?, ?)"
        ).bind(user_id, bot, device_fingerprint, ip).run();

        return jsonResponse({ status: "success", message: "Verification successful." });

    } catch (err) {
        return jsonResponse({ status: "fail", message: "Server Error: " + err.message }, 500);
    }
}

function JsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status: status,
        headers: { "Content-Type": "application/json" }
    });
}
