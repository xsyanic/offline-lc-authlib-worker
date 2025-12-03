export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        try {
            // ---------------------------
            // ROOT ROUTE
            // ---------------------------
            if (path === "/" && method === "GET")
                return rootRoute();

            // ---------------------------
            // STATUS ROUTE
            // ---------------------------
            if (path === "/api/status" && method === "GET")
                return json({ status: "ok" });

            // ---------------------------
            // AUTHLIB-INJECTOR API ROUTE
            // ---------------------------
            if (path === "/api/skin-authlib" && method === "GET")
                return authlibInjectorRoute();

            // ---------------------------
            // AUTH SERVER ROUTES
            // ---------------------------
            if (path === "/api/skin-authlib/authserver/authenticate" && method === "POST")
                return authenticate(request);

            if (path === "/api/skin-authlib/authserver/validate" && method === "POST")
                return validateToken();

            if (path === "/api/skin-authlib/authserver/refresh" && method === "POST")
                return refresh(request);

            // ---------------------------
            // SESSION SERVER ROUTES
            // ---------------------------
            if (path === "/api/skin-authlib/sessionserver/session/minecraft/join" && method === "POST")
                return joinProxy(request);

            if (path === "/api/skin-authlib/sessionserver/session/minecraft/hasJoined" && method === "GET")
                return hasJoinedProxy(url);

            if (path.startsWith("/api/skin-authlib/sessionserver/session/minecraft/profile/") && method === "GET") {
                const uuid = path.split("/").pop();
                return getProfile(uuid);
            }

            return new Response("Not Found", { status: 404 });

        } catch (err) {
            return new Response("Internal error: " + err, { status: 500 });
        }
    }
};


// ======================================================================
//                               JSON HELPER
// ======================================================================
function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { "Content-Type": "application/json" }
    });
}


// ======================================================================
//                           ROOT ROUTE
// ======================================================================
function rootRoute() {
    const headers = {
        "Content-Type": "application/json",
        "X-Authlib-Injector-API-Location": "/api/skin-authlib"
    };

    return new Response(
        JSON.stringify({ message: "Offline LC Authlib server" }),
        { status: 200, headers }
    );
}


// ======================================================================
//                     AUTHLIB-INJECTOR ROUTE
// ======================================================================
function authlibInjectorRoute() {
    const authlibData = {
        meta: {
            implementationName: "offline-lc-authlib",
            implementationVersion: "1.0.0",
            serverName: "OfflineLC",
            "feature.non_email_login": true,
            "feature.legacy_skin_api": true
        },
        skinDomains: [".syanic.org"]
    };

    return json(authlibData);
}


// ======================================================================
//                              CONSTANTS
// ======================================================================
const MOJANG_SESSION = "https://sessionserver.mojang.com/session/minecraft";


// ======================================================================
//                     AUTHENTICATE
// ======================================================================
async function authenticate(request) {
    const data = await request.json();
    const username = data.username;

    const profile_uuid = await offlineUUID(username);
    const uuid_unsigned = profile_uuid.replace(/-/g, "");

    const client_token = data.clientToken || null;
    const access_token = generateSpoofJWT();

    const profile_obj = {
        id: uuid_unsigned,
        name: username
    };

    const response = {
        accessToken: access_token,
        clientToken: client_token,
        availableProfiles: [profile_obj],
        selectedProfile: profile_obj
    };

    if (data.requestUser === true) {
        response.user = {
            id: uuid_unsigned,
            properties: []
        };
    }

    return json(response);
}


// ======================================================================
//                     VALIDATE
// ======================================================================
async function validateToken() {
    return new Response(null, { status: 204 });
}


// ======================================================================
//                     REFRESH
// ======================================================================
async function refresh(request) {
    const data = await request.json();

    if (!data?.accessToken) {
        return json({ error: "Forbidden", errorMessage: "Invalid token." }, 403);
    }

    return json({
        accessToken: data.accessToken,
        clientToken: data.clientToken
    });
}


// ======================================================================
//                     JOIN
// ======================================================================
async function joinProxy(request) {
    const body = await request.json();
    const uuid = body.selectedProfile;

    if (isPremiumUUID(uuid)) {
        const r = await fetch(`${MOJANG_SESSION}/join`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        return new Response(await r.arrayBuffer(), {
            status: r.status,
            headers: r.headers
        });
    }

    return json({ error: "Offline Accounts can't join this server." }, 403);
}


// ======================================================================
//                     HASJOINED
// ======================================================================
async function hasJoinedProxy(url) {
    const username = url.searchParams.get("username");

    if (await isPremiumUsername(username)) {
        const r = await fetch(`${MOJANG_SESSION}/hasJoined?${url.searchParams.toString()}`);

        return new Response(await r.arrayBuffer(), {
            status: r.status,
            headers: r.headers
        });
    }

    return json({ error: "Offline Accounts can't join this server." }, 403);
}


// ======================================================================
//                     PROFILE LOOKUP
// ======================================================================
async function getProfile(uuid) {
    if (isPremiumUUID(uuid)) {
        const url = `${MOJANG_SESSION}/profile/${uuid}?unsigned=true`;

        const r = await fetch(url);

        if (r.status !== 200)
            return json({ error: "Profile not found in Mojang Server" }, 404);

        const data = await r.json();
        return json(data);
    }

    return json({ error: "Offline Accounts have no profile." }, 403);
}


// ======================================================================
//                    HELPER: OFFLINE UUID V3 (MD5)
// ======================================================================
async function offlineUUID(name) {
    const base = "OfflinePlayer:" + name;

    const md5 = await crypto.subtle.digest("MD5", new TextEncoder().encode(base));
    let bytes = new Uint8Array(md5);

    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    return bytesToUUID(bytes);
}

function bytesToUUID(bytes) {
    const hex = [...bytes].map(x => x.toString(16).padStart(2, "0")).join("");
    return (
        hex.slice(0, 8) + "-" +
        hex.slice(8, 12) + "-" +
        hex.slice(12, 16) + "-" +
        hex.slice(16, 20) + "-" +
        hex.slice(20)
    );
}


// ======================================================================
//                       HELPER: PREMIUM CHECK
// ======================================================================
function isPremiumUUID(uuid) {
    uuid = uuid.replace(/-/g, "");
    return uuid[12] === "4";
}

async function isPremiumUsername(username) {
    const r = await fetch(
        `https://api.mojang.com/users/profiles/minecraft/${username}`
    );
    return r.status === 200;
}


// ======================================================================
//                       HELPER: SPOOF JWT
// ======================================================================
function generateSpoofJWT() {
    const now = Math.floor(Date.now() / 1000);
    const exp = Math.floor((Date.now() + 1000 * 60 * 60 * 24 * 365.25 * 7) / 1000);

    const header = { typ: "JWT", alg: "ES256" };
    const payload = {
        iat: now,
        sub: "xs|" + Math.floor(1_000_000 + Math.random() * 9_000_000),
        exp: exp,
        scope: "obtain_own_account_info minecraft_server_session",
        "syanic-client-token":
            crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID()
    };

    const signature = base64urlRandom(48);

    return (
        base64urlEncode(JSON.stringify(header)) + "." +
        base64urlEncode(JSON.stringify(payload)) + "." +
        signature
    );
}

function base64urlEncode(str) {
    return btoa(str)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

function base64urlRandom(bytes) {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return base64urlEncode(String.fromCharCode(...arr));
}
