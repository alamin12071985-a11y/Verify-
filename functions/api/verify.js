// functions/api/verify.js

export async function onRequestPost(context) {
    const { request, env } = context;

    try {
        // 1. Parse Data
        const data = await request.json();
        const { user_id, bot, botHash, device_fingerprint } = data;

        // Validation
        if (!user_id || !bot || !botHash) {
            return jsonError("Missing required parameters", 400);
        }

        // 2. Get Client IP (Cloudflare provides this automatically)
        const ip = request.headers.get("CF-Connecting-IP") || "Unknown";
        const userAgent = request.headers.get("User-Agent") || "Unknown";

        // 3. Check Ban List
        const isBanned = await env.DB.prepare(
            "SELECT user_id FROM banned_users WHERE user_id = ?"
        ).bind(user_id).first();

        if (isBanned) {
            return jsonError("User account is suspended.", 403);
        }

        // 4. Multi-Account Detection Logic
        // Logic A: Check if this Device Fingerprint is already used by ANOTHER user
        if (device_fingerprint) {
            const deviceCheck = await env.DB.prepare(
                "SELECT user_id FROM fingerprints WHERE fingerprint_hash = ? AND user_id != ?"
            ).bind(device_fingerprint, user_id).first();

            if (deviceCheck) {
                // Suspend the new account immediately to prevent farming
                return jsonError("Multi-account detected (Device Match). This device is already registered.", 403);
            }
        }

        // Logic B: Check if this IP is abused (More than 3 accounts on same IP - optional strict check)
        // This helps catch users who use different browsers but same WiFi
        const ipCheck = await env.DB.prepare(
            "SELECT COUNT(*) as count FROM fingerprints WHERE ip_address = ?"
        ).bind(ip).first();

        if (ipCheck && ipCheck.count >= 3) {
            // Return error if too many accounts on one IP (adjust limit as needed)
            // Note: Be careful with public WiFi. You might want to just 'Flag' instead of Block.
            // For this demo, we will Block.
            return jsonError("Suspicious activity detected (IP Limit Reached).", 403);
        }

        // 5. Check Existing Verification
        const existingUser = await env.DB.prepare(
            "SELECT id FROM fingerprints WHERE user_id = ? AND bot = ?"
        ).bind(user_id, bot).first();

        if (existingUser) {
            return new Response(JSON.stringify({
                status: "success",
                message: "Already verified."
            }), { headers: { "Content-Type": "application/json" } });
        }

        // 6. Insert New Verification Record
        await env.DB.prepare(
            "INSERT INTO fingerprints (user_id, bot, fingerprint_hash, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)"
        ).bind(user_id, bot, device_fingerprint || "no_fp", ip, userAgent).run();

        // 7. Success Response
        return new Response(JSON.stringify({
            status: "success",
            message: "Verification complete."
        }), { headers: { "Content-Type": "application/json" } });

    } catch (err) {
        return jsonError("Server Error: " + err.message, 500);
    }
}

function jsonError(msg, status) {
    return new Response(JSON.stringify({
        status: "fail",
        message: msg
    }), {
        status: status,
        headers: { "Content-Type": "application/json" }
    });
}
