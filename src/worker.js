const COOKIE_MAX_AGE = 60 * 60 * 24 * 7;
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }), env);
    }

    try {
      if (url.pathname === "/auth/github") return handleGithubStart(request, env);
      if (url.pathname === "/auth/github/callback") return handleGithubCallback(request, env);
      if (url.pathname === "/session") return withCors(await handleSession(request, env), env);
      if (url.pathname === "/save" && request.method === "POST") return withCors(await handleSave(request, env), env);
      if (url.pathname === "/new" && request.method === "POST") return withCors(await handleNew(request, env), env);
      if (url.pathname === "/delete" && request.method === "POST") return withCors(await handleDelete(request, env), env);
      if (url.pathname === "/logout") return withCors(handleLogout(env), env);

      return withCors(json({ error: "not found" }, 404), env);
    } catch (error) {
      return withCors(json({ error: error.message || "internal error" }, 500), env);
    }
  }
};

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...headers }
  });
}

function withCors(response, env) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", env.CORS_ORIGIN || "*");
  headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  headers.set("access-control-allow-headers", "authorization,content-type");
  headers.set("access-control-allow-credentials", "true");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function redirect(location, headers = {}) {
  return new Response(null, {
    status: 302,
    headers: { location, ...headers }
  });
}

async function handleGithubStart(request, env) {
  requireEnv(env, ["GITHUB_CLIENT_ID"]);
  const url = new URL(request.url);
  const state = crypto.randomUUID();
  const callback = `${url.origin}/auth/github/callback`;
  const authUrl = new URL("https://github.com/login/oauth/authorize");
  authUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", callback);
  authUrl.searchParams.set("scope", "read:user");
  authUrl.searchParams.set("state", state);

  const stateCookie = cookie("zakrad_oauth_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 600,
    path: "/"
  });

  return redirect(authUrl.toString(), { "set-cookie": stateCookie });
}

async function handleGithubCallback(request, env) {
  requireEnv(env, ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "SESSION_SECRET"]);
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const expectedState = readCookie(request, "zakrad_oauth_state");

  if (!code || !state || !expectedState || state !== expectedState) {
    return json({ error: "invalid oauth state" }, 401);
  }

  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json"
    },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code
    })
  });
  const tokenPayload = await tokenResponse.json();
  if (!tokenPayload.access_token) return json({ error: "github token exchange failed" }, 401);

  const userResponse = await fetch("https://api.github.com/user", {
    headers: githubHeaders(tokenPayload.access_token)
  });
  const user = await userResponse.json();
  if (user.login !== env.GITHUB_ALLOWED_LOGIN) return json({ error: "not allowed" }, 403);

  const session = await signSession({
    login: user.login,
    exp: Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE
  }, env);

  const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
  headers.append("set-cookie", cookie(env.SESSION_COOKIE_NAME || "zakrad_editor_session", session, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: COOKIE_MAX_AGE,
    path: "/"
  }));
  headers.append("set-cookie", cookie("zakrad_oauth_state", "", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 0,
    path: "/"
  }));

  const openerOrigin = env.CORS_ORIGIN || "*";
  const authHash = `#${new URLSearchParams({
    zakrad_auth: session,
    login: user.login
  }).toString()}`;
  return new Response(`<!doctype html>
<meta charset="utf-8">
<script>
  (function () {
    try {
      if (window.opener && !window.opener.closed) {
        try {
          window.opener.location.hash = ${JSON.stringify(authHash)};
          window.opener.focus();
        } catch (error) {
          try {
            window.opener.postMessage(${JSON.stringify({
              type: "zakrad-auth",
              token: session,
              login: user.login
            })}, ${JSON.stringify(openerOrigin)});
          } catch (messageError) {}
        }
      }
    } catch (error) {
      document.body.textContent = "Auth complete, but could not notify the opener.";
    }
    window.close();
  })();
</script>
<p>Authenticated. You can close this tab.</p>`, { headers });
}

async function handleSession(request, env) {
  const session = await readSession(request, env);
  return json({ authenticated: Boolean(session), login: session?.login || null });
}

async function handleSave(request, env) {
  await requireSession(request, env);
  const body = await request.json();
  const path = normalizePath(body.path);
  const content = String(body.content ?? "");
  assertAllowedPath(path);
  await putGithubFile(env, path, content, `chore(site): update ${path}`);
  return json({ ok: true, path });
}

async function handleNew(request, env) {
  await requireSession(request, env);
  const body = await request.json();
  const path = normalizePath(body.path);
  const kind = body.kind === "folder" || path.endsWith("/") ? "folder" : "file";
  const targetPath = kind === "folder" ? `${path.replace(/\/$/, "")}/.gitkeep` : path;
  assertAllowedPath(targetPath);
  await putGithubFile(env, targetPath, body.content ? String(body.content) : "", `chore(site): create ${targetPath}`);
  return json({ ok: true, path: targetPath });
}

async function handleDelete(request, env) {
  await requireSession(request, env);
  const body = await request.json();
  const path = normalizePath(body.path);
  const kind = body.kind === "folder" ? "folder" : "file";
  const targetPath = kind === "folder" ? `${path.replace(/\/$/, "")}/.gitkeep` : path;
  assertAllowedPath(targetPath);
  await deleteGithubFile(env, targetPath, `chore(site): delete ${targetPath}`);
  return json({ ok: true, path: targetPath });
}

function handleLogout(env) {
  return json({ ok: true }, 200, {
    "set-cookie": cookie(env.SESSION_COOKIE_NAME, "", {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      maxAge: 0,
      path: "/"
    })
  });
}

async function putGithubFile(env, path, content, message) {
  requireEnv(env, ["GITHUB_OWNER", "GITHUB_REPO", "GITHUB_BRANCH", "GITHUB_TOKEN"]);
  const base = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${encodeURIComponentPath(path)}`;
  const existingResponse = await fetch(`${base}?ref=${encodeURIComponent(env.GITHUB_BRANCH)}`, {
    headers: githubHeaders(env.GITHUB_TOKEN)
  });
  const existing = existingResponse.ok ? await existingResponse.json() : null;
  const putResponse = await fetch(base, {
    method: "PUT",
    headers: githubHeaders(env.GITHUB_TOKEN, { "content-type": "application/json" }),
    body: JSON.stringify({
      message,
      branch: env.GITHUB_BRANCH,
      content: base64(content),
      sha: existing?.sha
    })
  });

  if (!putResponse.ok) {
    const detail = await putResponse.text();
    throw new Error(`github write failed: ${putResponse.status} ${detail}`);
  }
}

async function deleteGithubFile(env, path, message) {
  requireEnv(env, ["GITHUB_OWNER", "GITHUB_REPO", "GITHUB_BRANCH", "GITHUB_TOKEN"]);
  const base = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${encodeURIComponentPath(path)}`;
  const existingResponse = await fetch(`${base}?ref=${encodeURIComponent(env.GITHUB_BRANCH)}`, {
    headers: githubHeaders(env.GITHUB_TOKEN)
  });
  if (!existingResponse.ok) {
    const detail = await existingResponse.text();
    throw new Error(`github lookup failed: ${existingResponse.status} ${detail}`);
  }
  const existing = await existingResponse.json();
  const deleteResponse = await fetch(base, {
    method: "DELETE",
    headers: githubHeaders(env.GITHUB_TOKEN, { "content-type": "application/json" }),
    body: JSON.stringify({
      message,
      branch: env.GITHUB_BRANCH,
      sha: existing.sha
    })
  });

  if (!deleteResponse.ok) {
    const detail = await deleteResponse.text();
    throw new Error(`github delete failed: ${deleteResponse.status} ${detail}`);
  }
}

function githubHeaders(token, extra = {}) {
  return {
    authorization: `Bearer ${token}`,
    accept: "application/vnd.github+json",
    "user-agent": "zakrad-editor-api",
    "x-github-api-version": "2022-11-28",
    ...extra
  };
}

async function requireSession(request, env) {
  const session = await readSession(request, env);
  if (!session) throw new Error("not authenticated");
  return session;
}

async function readSession(request, env) {
  const bearer = readBearerToken(request);
  if (bearer) {
    const session = await verifySession(bearer, env);
    if (session && session.exp >= Math.floor(Date.now() / 1000)) return session;
  }

  const raw = readCookie(request, env.SESSION_COOKIE_NAME || "zakrad_editor_session");
  if (!raw) return null;
  const session = await verifySession(raw, env);
  if (!session || session.exp < Math.floor(Date.now() / 1000)) return null;
  return session;
}

function readBearerToken(request) {
  const header = request.headers.get("authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : "";
}

async function signSession(payload, env) {
  const body = base64Url(JSON.stringify(payload));
  const signature = await hmac(body, env.SESSION_SECRET);
  return `${body}.${signature}`;
}

async function verifySession(value, env) {
  if (!env.SESSION_SECRET) return null;
  const [body, signature] = value.split(".");
  if (!body || !signature) return null;
  const expected = await hmac(body, env.SESSION_SECRET);
  if (signature !== expected) return null;
  try {
    return JSON.parse(textDecoder.decode(base64UrlDecode(body)));
  } catch {
    return null;
  }
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(value));
  return base64Url(signature);
}

function cookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  return parts.join("; ");
}

function readCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  return header.split(";").map((part) => part.trim()).reduce((found, part) => {
    if (found) return found;
    const [key, ...value] = part.split("=");
    return key === name ? decodeURIComponent(value.join("=")) : "";
  }, "");
}

function normalizePath(path) {
  return String(path || "").trim().replace(/^\/+/, "").replace(/\/+/g, "/");
}

function assertAllowedPath(path) {
  if (!path || path.startsWith(".") || path.split("/").includes("..")) {
    throw new Error("unsafe path");
  }

  const allowed =
    path === "README.md" ||
    path === "PROJECTS.md" ||
    path === "index.html" ||
    path.startsWith("docs/") ||
    path.startsWith("content/");

  if (!allowed) throw new Error(`path not allowed: ${path}`);
}

function encodeURIComponentPath(path) {
  return path.split("/").map(encodeURIComponent).join("/");
}

function base64(value) {
  const bytes = textEncoder.encode(value);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    const chunk = bytes.subarray(i, i + 0x8000);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64Url(value) {
  const bytes = typeof value === "string" ? textEncoder.encode(value) : new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlDecode(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function requireEnv(env, names) {
  const missing = names.filter((name) => !env[name]);
  if (missing.length) throw new Error(`missing env: ${missing.join(", ")}`);
}
