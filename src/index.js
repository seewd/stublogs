const DEFAULT_RESERVED_SLUGS = [
  "app",
  "www",
  "api",
  "admin",
  "assets",
  "static",
  "img",
  "files",
  "forum",
  "mail",
  "mx",
  "ftp",
  "ssh",
  "vpn",
  "cdn",
  "docs",
  "status",
  "blog",
  "dashboard",
];

const SESSION_COOKIE = "stublogs_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error("Unhandled error", error);
      return json({ error: "Internal server error" }, 500);
    }
  },
};

export function getReservedSlugs(env) {
  const configured = String(env.RESERVED_SLUGS || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  return new Set([...DEFAULT_RESERVED_SLUGS, ...configured]);
}

export function validateSlug(rawSlug, reservedSlugs = new Set()) {
  const slug = String(rawSlug || "").trim().toLowerCase();

  if (slug.length < 2 || slug.length > 30) {
    return { ok: false, reason: "slug-length" };
  }

  if (!/^[a-z0-9-]+$/.test(slug)) {
    return { ok: false, reason: "slug-charset" };
  }

  if (slug.startsWith("-") || slug.endsWith("-")) {
    return { ok: false, reason: "slug-edge-dash" };
  }

  if (slug.includes("--")) {
    return { ok: false, reason: "slug-double-dash" };
  }

  const blockedTerms = ["official", "support", "staff", "security"];
  if (blockedTerms.includes(slug)) {
    return { ok: false, reason: "slug-sensitive" };
  }

  if (reservedSlugs.has(slug)) {
    return { ok: false, reason: "slug-reserved" };
  }

  return { ok: true, slug };
}

export function validatePostSlug(rawSlug) {
  const slug = String(rawSlug || "").trim().toLowerCase();

  if (slug.length < 1 || slug.length > 80) {
    return { ok: false, reason: "post-slug-length" };
  }

  if (!/^[a-z0-9-]+$/.test(slug)) {
    return { ok: false, reason: "post-slug-charset" };
  }

  if (slug.startsWith("-") || slug.endsWith("-")) {
    return { ok: false, reason: "post-slug-edge-dash" };
  }

  if (slug.includes("--")) {
    return { ok: false, reason: "post-slug-double-dash" };
  }

  return { ok: true, slug };
}

export function getHostSlug(hostname, baseDomain) {
  const host = String(hostname || "").toLowerCase();
  const base = String(baseDomain || "").toLowerCase();

  if (host === base) {
    return null;
  }

  if (!host.endsWith(`.${base}`)) {
    return null;
  }

  const prefix = host.slice(0, host.length - base.length - 1);
  if (!prefix) {
    return null;
  }

  const labels = prefix.split(".").filter(Boolean);
  return labels.length ? labels[0] : null;
}

export function slugifyValue(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80);
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = normalizePath(url.pathname);
  const hostHeader = request.headers.get("host") || url.host;
  const hostname = hostHeader.split(":")[0].toLowerCase();
  const baseDomain = String(env.BASE_DOMAIN || "bdfz.net").toLowerCase();
  const hostSlug = getHostSlug(hostname, baseDomain);
  const reservedSlugs = getReservedSlugs(env);

  if (path === "/healthz") {
    return text("ok");
  }

  if (path.startsWith("/api/")) {
    if (request.method === "OPTIONS") {
      return buildApiPreflightResponse(request, env);
    }

    const response = await handleApi(request, env, {
      path,
      url,
      hostSlug,
      baseDomain,
      reservedSlugs,
    });
    return withCors(response, request, env);
  }

  if (hostSlug === null) {
    if (path === "/") {
      return html(renderRootPage(baseDomain), 200);
    }

    if (path === "/admin") {
      const site = String(url.searchParams.get("site") || "")
        .trim()
        .toLowerCase();
      const validation = validateSlug(site, reservedSlugs);
      if (validation.ok) {
        return Response.redirect(`https://${site}.${baseDomain}/admin`, 302);
      }
      return html(renderRootAdminHelp(baseDomain), 200);
    }

    if (path === "/robots.txt") {
      return text("User-agent: *\nAllow: /\n");
    }

    return notFound();
  }

  if (reservedSlugs.has(hostSlug)) {
    return notFound("This subdomain is reserved");
  }

  const site = await getSiteBySlug(env, hostSlug);

  if (!site) {
    if (path === "/" || path === "/admin") {
      return html(renderClaimPage(hostSlug, baseDomain), 200);
    }
    return notFound("Site not found");
  }

  if (path === "/admin") {
    const authed = await isSiteAuthenticated(request, env, site.slug);
    return html(renderAdminPage(site, authed, baseDomain), 200);
  }

  if (path === "/") {
    const posts = await listPosts(env, site.id, false);
    return html(renderSiteHomePage(site, posts, baseDomain), 200);
  }

  if (path === "/robots.txt") {
    return text("User-agent: *\nAllow: /\n");
  }

  const segments = path.slice(1).split("/").filter(Boolean);
  if (segments.length !== 1) {
    return notFound();
  }

  const postSlug = segments[0].toLowerCase();
  const post = await getPostMeta(env, site.id, postSlug, false);
  if (!post) {
    return notFound("Post not found");
  }

  const file = await githubReadFile(env, getPostFilePath(site.slug, post.postSlug));
  if (!file) {
    return notFound("Post content missing");
  }

  const articleHtml = renderMarkdown(file.content);
  return html(renderPostPage(site, post, articleHtml, baseDomain), 200);
}

async function handleApi(request, env, context) {
  const { path, url, hostSlug, baseDomain, reservedSlugs } = context;

  if (request.method === "GET" && path === "/api/check-slug") {
    const slug = String(url.searchParams.get("slug") || "")
      .trim()
      .toLowerCase();
    const validation = validateSlug(slug, reservedSlugs);
    if (!validation.ok) {
      return json({ available: false, reason: validation.reason }, 200);
    }

    const existing = await getSiteBySlug(env, slug);
    if (existing) {
      return json({ available: false, reason: "slug-already-exists" }, 200);
    }

    return json({ available: true }, 200);
  }

  if (request.method === "POST" && path === "/api/register") {
    const body = await readJson(request);

    const slug = String(body.slug || "")
      .trim()
      .toLowerCase();
    const displayName = sanitizeName(body.displayName || slug) || slug;
    const description = sanitizeDescription(body.description || "");
    const adminPassword = String(body.adminPassword || "");
    const inviteCode = String(body.inviteCode || "").trim();

    const inviteCodes = getInviteCodes(env);
    if (!inviteCodes.size) {
      return json({ error: "Invite codes are not configured" }, 503);
    }

    if (!inviteCodes.has(inviteCode)) {
      return json({ error: "Invalid invite code" }, 403);
    }

    if (hostSlug && !reservedSlugs.has(hostSlug) && slug !== hostSlug) {
      return json({ error: "Slug must match current hostname" }, 400);
    }

    const validation = validateSlug(slug, reservedSlugs);
    if (!validation.ok) {
      return json({ error: "Invalid slug", reason: validation.reason }, 400);
    }

    if (adminPassword.length < 8) {
      return json({ error: "Password must be at least 8 characters" }, 400);
    }

    const existing = await getSiteBySlug(env, slug);
    if (existing) {
      return json({ error: "Slug already exists" }, 409);
    }

    const now = new Date().toISOString();
    const passwordHash = await createPasswordHash(adminPassword, env);

    let siteId = null;
    try {
      const insert = await env.DB.prepare(
        `INSERT INTO sites (slug, display_name, description, admin_secret_hash, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
        .bind(slug, displayName, description, passwordHash, now, now)
        .run();

      siteId = Number(insert.meta?.last_row_id || 0);
      if (!siteId) {
        const createdSite = await getSiteBySlug(env, slug);
        siteId = Number(createdSite?.id || 0);
      }

      const siteConfig = JSON.stringify(
        {
          slug,
          displayName,
          description,
          createdAt: now,
          exportVersion: 1,
        },
        null,
        2
      );

      await githubWriteFile(
        env,
        getSiteConfigPath(slug),
        `${siteConfig}\n`,
        `feat(${slug}): initialize blog`
      );

      const welcomeSlug = "hello-world";
      await githubWriteFile(
        env,
        getPostFilePath(slug, welcomeSlug),
        buildWelcomePost(slug, displayName, baseDomain),
        `feat(${slug}): add welcome post`
      );

      await upsertPostMeta(
        env,
        siteId,
        welcomeSlug,
        "Hello World",
        "你的第一篇文章，開始編輯它吧。",
        1,
        now,
        now
      );
    } catch (error) {
      console.error("Failed to register site", error);

      if (siteId) {
        await env.DB.batch([
          env.DB.prepare("DELETE FROM posts WHERE site_id = ?").bind(siteId),
          env.DB.prepare("DELETE FROM sites WHERE id = ?").bind(siteId),
        ]);
      }

      return json(
        {
          error: "Failed to initialize site",
          detail: String(error && error.message ? error.message : error),
        },
        502
      );
    }

    return json(
      {
        ok: true,
        site: slug,
        siteUrl: `https://${slug}.${baseDomain}`,
      },
      201
    );
  }

  if (request.method === "POST" && path === "/api/login") {
    if (!hostSlug) {
      return json({ error: "Login must happen on site subdomain" }, 400);
    }

    const body = await readJson(request);
    const password = String(body.password || "");
    const slug = String(body.slug || hostSlug)
      .trim()
      .toLowerCase();

    if (slug !== hostSlug) {
      return json({ error: "Slug mismatch" }, 400);
    }

    const site = await getSiteBySlug(env, slug);
    if (!site) {
      return json({ error: "Site not found" }, 404);
    }

    const verified = await verifyPassword(password, site.adminSecretHash, env);
    if (!verified) {
      return json({ error: "Invalid credentials" }, 401);
    }

    const token = await createSessionToken(site.slug, env);
    const response = json({ ok: true }, 200);
    return withCookie(response, buildSessionCookie(token));
  }

  if (request.method === "POST" && path === "/api/logout") {
    const response = json({ ok: true }, 200);
    return withCookie(response, buildClearSessionCookie());
  }

  if (request.method === "GET" && path === "/api/list-posts") {
    let slug = hostSlug;
    if (!slug) {
      slug = String(url.searchParams.get("slug") || "")
        .trim()
        .toLowerCase();
    }

    if (!slug) {
      return json({ error: "Missing slug" }, 400);
    }

    const site = await getSiteBySlug(env, slug);
    if (!site) {
      return json({ error: "Site not found" }, 404);
    }

    let includeDrafts = url.searchParams.get("includeDrafts") === "1";
    if (includeDrafts) {
      const authed = await isSiteAuthenticated(request, env, site.slug);
      if (!authed) {
        includeDrafts = false;
      }
    }

    const posts = await listPosts(env, site.id, includeDrafts);
    return json(
      {
        site: {
          slug: site.slug,
          displayName: site.displayName,
          description: site.description,
        },
        posts,
      },
      200
    );
  }

  if (request.method === "GET" && path.startsWith("/api/posts/")) {
    if (!hostSlug) {
      return json({ error: "Missing site context" }, 400);
    }

    const site = await getSiteBySlug(env, hostSlug);
    if (!site) {
      return json({ error: "Site not found" }, 404);
    }

    const authed = await isSiteAuthenticated(request, env, site.slug);
    if (!authed) {
      return json({ error: "Unauthorized" }, 401);
    }

    const postSlug = decodeURIComponent(path.slice("/api/posts/".length)).toLowerCase();
    if (!postSlug || postSlug.includes("/")) {
      return json({ error: "Invalid post slug" }, 400);
    }

    const post = await getPostMeta(env, site.id, postSlug, true);
    if (!post) {
      return json({ error: "Post not found" }, 404);
    }

    const file = await githubReadFile(env, getPostFilePath(site.slug, post.postSlug));
    return json(
      {
        post: {
          ...post,
          content: file ? file.content : "",
        },
      },
      200
    );
  }

  if (request.method === "POST" && path === "/api/posts") {
    if (!hostSlug) {
      return json({ error: "Missing site context" }, 400);
    }

    const site = await getSiteBySlug(env, hostSlug);
    if (!site) {
      return json({ error: "Site not found" }, 404);
    }

    const authed = await isSiteAuthenticated(request, env, site.slug);
    if (!authed) {
      return json({ error: "Unauthorized" }, 401);
    }

    const body = await readJson(request);

    const title = sanitizeTitle(body.title || "");
    const requestedSlug = String(body.postSlug || "").trim().toLowerCase();
    const postSlug = requestedSlug || slugifyValue(title);
    const description = sanitizeDescription(body.description || "");
    const content = String(body.content || "");
    const published = Boolean(body.published) ? 1 : 0;

    if (!title) {
      return json({ error: "Title is required" }, 400);
    }

    const validation = validatePostSlug(postSlug);
    if (!validation.ok) {
      return json({ error: "Invalid post slug", reason: validation.reason }, 400);
    }

    const now = new Date().toISOString();

    try {
      await githubWriteFile(
        env,
        getPostFilePath(site.slug, postSlug),
        content,
        `feat(${site.slug}): update post ${postSlug}`
      );

      await upsertPostMeta(
        env,
        site.id,
        postSlug,
        title,
        description,
        published,
        now,
        now
      );
    } catch (error) {
      console.error("Failed to save post", error);
      return json(
        {
          error: "Failed to save post",
          detail: String(error && error.message ? error.message : error),
        },
        502
      );
    }

    return json(
      {
        ok: true,
        post: {
          postSlug,
          title,
          description,
          published,
          updatedAt: now,
        },
      },
      200
    );
  }

  if (request.method === "GET" && path === "/api/export") {
    if (!hostSlug) {
      return json({ error: "Missing site context" }, 400);
    }

    const site = await getSiteBySlug(env, hostSlug);
    if (!site) {
      return json({ error: "Site not found" }, 404);
    }

    const authed = await isSiteAuthenticated(request, env, site.slug);
    if (!authed) {
      return json({ error: "Unauthorized" }, 401);
    }

    const posts = await listPosts(env, site.id, true);
    const exportedPosts = [];

    for (const post of posts) {
      const file = await githubReadFile(env, getPostFilePath(site.slug, post.postSlug));
      exportedPosts.push({
        ...post,
        content: file ? file.content : "",
      });
    }

    const payload = {
      exportedAt: new Date().toISOString(),
      site: {
        slug: site.slug,
        displayName: site.displayName,
        description: site.description,
        createdAt: site.createdAt,
      },
      posts: exportedPosts,
    };

    const filename = `${site.slug}-export-${new Date().toISOString().slice(0, 10)}.json`;
    return new Response(JSON.stringify(payload, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": `attachment; filename="${filename}"`,
      },
    });
  }

  return notFound();
}

async function getSiteBySlug(env, slug) {
  return env.DB.prepare(
    `SELECT
      id,
      slug,
      display_name AS displayName,
      description,
      admin_secret_hash AS adminSecretHash,
      created_at AS createdAt,
      updated_at AS updatedAt
    FROM sites
    WHERE slug = ?
    LIMIT 1`
  )
    .bind(slug)
    .first();
}

async function listPosts(env, siteId, includeDrafts = false) {
  const sql = includeDrafts
    ? `SELECT
        post_slug AS postSlug,
        title,
        description,
        published,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM posts
      WHERE site_id = ?
      ORDER BY updated_at DESC`
    : `SELECT
        post_slug AS postSlug,
        title,
        description,
        published,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM posts
      WHERE site_id = ? AND published = 1
      ORDER BY updated_at DESC`;

  const result = await env.DB.prepare(sql).bind(siteId).all();
  return result.results || [];
}

async function getPostMeta(env, siteId, postSlug, includeDrafts = false) {
  const sql = includeDrafts
    ? `SELECT
        post_slug AS postSlug,
        title,
        description,
        published,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM posts
      WHERE site_id = ? AND post_slug = ?
      LIMIT 1`
    : `SELECT
        post_slug AS postSlug,
        title,
        description,
        published,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM posts
      WHERE site_id = ? AND post_slug = ? AND published = 1
      LIMIT 1`;

  return env.DB.prepare(sql).bind(siteId, postSlug).first();
}

async function upsertPostMeta(
  env,
  siteId,
  postSlug,
  title,
  description,
  published,
  updatedAt,
  createdAt
) {
  const created = createdAt || updatedAt;

  return env.DB.prepare(
    `INSERT INTO posts (site_id, post_slug, title, description, published, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(site_id, post_slug)
     DO UPDATE SET
       title = excluded.title,
       description = excluded.description,
       published = excluded.published,
       updated_at = excluded.updated_at`
  )
    .bind(siteId, postSlug, title, description, published, created, updatedAt)
    .run();
}

function getGithubConfig(env) {
  const owner = String(env.GITHUB_OWNER || "").trim();
  const repo = String(env.GITHUB_REPO || "").trim();
  const branch = String(env.GITHUB_BRANCH || "main").trim();
  const token = String(env.GITHUB_TOKEN || "").trim();

  if (!owner || !repo || !token) {
    throw new Error("Missing GitHub config: GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN");
  }

  return { owner, repo, branch, token };
}

async function githubRequest(env, path, init = {}) {
  const config = getGithubConfig(env);
  const url = `https://api.github.com/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}${path}`;

  const response = await fetch(url, {
    method: init.method || "GET",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${config.token}`,
      "User-Agent": "stublogs-worker",
      ...(init.headers || {}),
    },
    body: init.body,
  });

  return response;
}

async function githubReadFile(env, filePath) {
  const config = getGithubConfig(env);
  const encodedPath = encodeGitHubPath(filePath);
  const response = await githubRequest(
    env,
    `/contents/${encodedPath}?ref=${encodeURIComponent(config.branch)}`
  );

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`GitHub read failed: ${response.status} ${detail}`);
  }

  const data = await response.json();
  if (!data || Array.isArray(data) || typeof data.content !== "string") {
    return null;
  }

  return {
    sha: data.sha,
    content: fromBase64Utf8(data.content),
  };
}

async function githubWriteFile(env, filePath, content, message) {
  const config = getGithubConfig(env);
  const existing = await githubReadFile(env, filePath);
  const encodedPath = encodeGitHubPath(filePath);

  const payload = {
    message,
    branch: config.branch,
    content: toBase64Utf8(content),
  };

  if (existing && existing.sha) {
    payload.sha = existing.sha;
  }

  const response = await githubRequest(env, `/contents/${encodedPath}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`GitHub write failed: ${response.status} ${detail}`);
  }

  return response.json();
}

function encodeGitHubPath(path) {
  return String(path)
    .split("/")
    .filter(Boolean)
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

function getSiteConfigPath(siteSlug) {
  return `sites/${siteSlug}/site.json`;
}

function getPostFilePath(siteSlug, postSlug) {
  return `sites/${siteSlug}/posts/${postSlug}.md`;
}

async function createPasswordHash(password, env) {
  const salt = randomHex(16);
  const digest = await sha256Hex(`${salt}:${password}:${getSessionSecret(env)}`);
  return `${salt}:${digest}`;
}

async function verifyPassword(password, stored, env) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) {
    return false;
  }

  const digest = await sha256Hex(`${salt}:${password}:${getSessionSecret(env)}`);
  return timingSafeEqual(hash, digest);
}

async function createSessionToken(slug, env) {
  const payload = {
    slug,
    exp: Date.now() + SESSION_TTL_SECONDS * 1000,
  };

  const payloadEncoded = toBase64Url(JSON.stringify(payload));
  const signature = await hmacHex(payloadEncoded, getSessionSecret(env));
  return `${payloadEncoded}.${signature}`;
}

async function verifySessionToken(token, env) {
  const raw = String(token || "");
  if (!raw.includes(".")) {
    return null;
  }

  const [payloadEncoded, signature] = raw.split(".");
  if (!payloadEncoded || !signature) {
    return null;
  }

  const expected = await hmacHex(payloadEncoded, getSessionSecret(env));
  if (!timingSafeEqual(signature, expected)) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(fromBase64Url(payloadEncoded));
  } catch {
    return null;
  }

  if (!payload || typeof payload.slug !== "string" || typeof payload.exp !== "number") {
    return null;
  }

  if (Date.now() > payload.exp) {
    return null;
  }

  return payload;
}

async function isSiteAuthenticated(request, env, slug) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const token = cookies[SESSION_COOKIE];
  if (!token) {
    return false;
  }

  let session;
  try {
    session = await verifySessionToken(token, env);
  } catch (error) {
    console.error("Session verification failed", error);
    return false;
  }

  if (!session) {
    return false;
  }

  return session.slug === slug;
}

function buildSessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`;
}

function buildClearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function withCookie(response, cookieValue) {
  const headers = new Headers(response.headers);
  headers.append("Set-Cookie", cookieValue);
  return new Response(response.body, {
    status: response.status,
    headers,
  });
}

function parseCookies(cookieHeader) {
  const entries = String(cookieHeader || "")
    .split(";")
    .map((value) => value.trim())
    .filter(Boolean)
    .map((pair) => {
      const [name, ...rest] = pair.split("=");
      return [name, rest.join("=")];
    });

  return Object.fromEntries(entries);
}

function getInviteCodes(env) {
  return new Set(
    String(env.INVITE_CODES || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
  );
}

function getAllowedCorsOrigins(env) {
  return new Set(
    String(env.CORS_ALLOWED_ORIGINS || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
  );
}

function resolveCorsOrigin(request, env) {
  const origin = String(request.headers.get("origin") || "").trim();
  if (!origin) {
    return null;
  }

  const allowedOrigins = getAllowedCorsOrigins(env);
  if (!allowedOrigins.size) {
    return null;
  }

  if (allowedOrigins.has("*")) {
    return "*";
  }

  return allowedOrigins.has(origin) ? origin : null;
}

function withCors(response, request, env) {
  const allowedOrigin = resolveCorsOrigin(request, env);
  if (!allowedOrigin) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", allowedOrigin);
  headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type");
  headers.set("Vary", "Origin");

  return new Response(response.body, {
    status: response.status,
    headers,
  });
}

function buildApiPreflightResponse(request, env) {
  const allowedOrigin = resolveCorsOrigin(request, env);
  if (!allowedOrigin) {
    return new Response("Forbidden origin", { status: 403 });
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
    },
  });
}

function getSessionSecret(env) {
  const secret = String(env.SESSION_SECRET || "").trim();
  if (!secret) {
    throw new Error("Missing SESSION_SECRET");
  }
  return secret;
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value) {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  const bytes = new Uint8Array(signature);
  return Array.from(bytes, (item) => item.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(left, right) {
  const a = String(left || "");
  const b = String(right || "");

  if (a.length !== b.length) {
    return false;
  }

  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return mismatch === 0;
}

function toBase64Utf8(value) {
  const bytes = new TextEncoder().encode(String(value || ""));
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function fromBase64Utf8(base64Value) {
  const normalized = String(base64Value || "").replace(/\n/g, "");
  const binary = atob(normalized);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function toBase64Url(value) {
  return toBase64Utf8(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const base64 = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (base64.length % 4)) % 4;
  return fromBase64Utf8(base64 + "=".repeat(padding));
}

function normalizePath(pathname) {
  const path = String(pathname || "/");
  if (path.length > 1 && path.endsWith("/")) {
    return path.slice(0, -1);
  }
  return path;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function sanitizeName(value) {
  return String(value || "")
    .trim()
    .slice(0, 60);
}

function sanitizeTitle(value) {
  return String(value || "")
    .trim()
    .slice(0, 120);
}

function sanitizeDescription(value) {
  return String(value || "")
    .trim()
    .slice(0, 240);
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function text(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
    },
  });
}

function notFound(message = "Not found") {
  return html(renderSimpleMessage("404", message), 404);
}

function renderRootPage(baseDomain) {
  return renderLayout(
    "Stublogs",
    `
    <section class="panel">
      <p class="eyebrow">bdfz.net student blogs</p>
      <h1>開一個 ${escapeHtml(baseDomain)} 子域名 Blog</h1>
      <p class="muted">每位學生可選擇自己的 <code>xxx</code>，站點會是 <code>https://xxx.${escapeHtml(baseDomain)}</code>。</p>

      <form id="register-form" class="stack" autocomplete="off">
        <label>子域名 slug</label>
        <input id="slug" name="slug" placeholder="alice" minlength="2" maxlength="30" required />

        <label>顯示名稱</label>
        <input id="displayName" name="displayName" placeholder="Alice" maxlength="60" required />

        <label>管理密碼</label>
        <input id="adminPassword" name="adminPassword" type="password" minlength="8" required />

        <label>註冊邀請碼</label>
        <input id="inviteCode" name="inviteCode" placeholder="請輸入邀請碼" required />

        <label>站點簡介（可選）</label>
        <input id="description" name="description" maxlength="240" placeholder="這裡寫你的簡介" />

        <button type="submit">建立 Blog</button>
      </form>

      <p id="status" class="muted"></p>
    </section>

    <script>
      const statusEl = document.getElementById("status");
      const form = document.getElementById("register-form");
      const slugInput = document.getElementById("slug");
      const nameInput = document.getElementById("displayName");

      let timer = null;

      function setStatus(message, isError = false) {
        statusEl.textContent = message;
        statusEl.style.color = isError ? "#ae3a22" : "#6b6357";
      }

      async function checkSlug() {
        const slug = slugInput.value.trim().toLowerCase();
        if (!slug) {
          setStatus("");
          return;
        }

        try {
          const response = await fetch('/api/check-slug?slug=' + encodeURIComponent(slug));
          const payload = await response.json();
          if (payload.available) {
            setStatus('可用：' + slug + '.${escapeHtml(baseDomain)}');
          } else {
            setStatus('不可用（' + (payload.reason || 'unknown') + '）', true);
          }
        } catch {
          setStatus('無法檢查 slug，請稍後再試', true);
        }
      }

      slugInput.addEventListener('input', () => {
        const value = slugInput.value
          .toLowerCase()
          .replace(/[^a-z0-9-]/g, '')
          .replace(/--+/g, '-')
          .replace(/^-|-$/g, '')
          .slice(0, 30);
        slugInput.value = value;

        if (!nameInput.value.trim()) {
          nameInput.value = value;
        }

        clearTimeout(timer);
        timer = setTimeout(checkSlug, 220);
      });

      form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const payload = {
          slug: slugInput.value.trim().toLowerCase(),
          displayName: nameInput.value.trim(),
          adminPassword: document.getElementById('adminPassword').value,
          inviteCode: document.getElementById('inviteCode').value.trim(),
          description: document.getElementById('description').value.trim(),
        };

        setStatus('正在建立...');

        try {
          const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          const result = await response.json();

          if (!response.ok) {
            setStatus(result.error || '建立失敗', true);
            return;
          }

          setStatus('建立成功，跳轉中...');
          window.location.href = result.siteUrl + '/admin';
        } catch {
          setStatus('建立失敗，請稍後重試', true);
        }
      });
    </script>
  `
  );
}

function renderClaimPage(slug, baseDomain) {
  return renderLayout(
    `${slug}.${baseDomain}`,
    `
    <section class="panel">
      <p class="eyebrow">claim this subdomain</p>
      <h1>建立 <code>${escapeHtml(slug)}.${escapeHtml(baseDomain)}</code></h1>

      <form id="claim-form" class="stack" autocomplete="off">
        <label>子域名</label>
        <input id="slug" value="${escapeHtml(slug)}" readonly />

        <label>顯示名稱</label>
        <input id="displayName" name="displayName" maxlength="60" placeholder="${escapeHtml(slug)}" required />

        <label>管理密碼</label>
        <input id="adminPassword" type="password" minlength="8" required />

        <label>註冊邀請碼</label>
        <input id="inviteCode" placeholder="請輸入邀請碼" required />

        <label>站點簡介（可選）</label>
        <input id="description" maxlength="240" placeholder="這裡寫你的簡介" />

        <button type="submit">建立並進入後台</button>
      </form>

      <p id="status" class="muted"></p>
    </section>

    <script>
      const form = document.getElementById('claim-form');
      const statusEl = document.getElementById('status');

      function setStatus(message, isError = false) {
        statusEl.textContent = message;
        statusEl.style.color = isError ? '#ae3a22' : '#6b6357';
      }

      form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const payload = {
          slug: ${JSON.stringify(slug)},
          displayName: document.getElementById('displayName').value.trim() || ${JSON.stringify(slug)},
          adminPassword: document.getElementById('adminPassword').value,
          inviteCode: document.getElementById('inviteCode').value.trim(),
          description: document.getElementById('description').value.trim(),
        };

        setStatus('正在建立...');

        try {
          const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });

          const result = await response.json();
          if (!response.ok) {
            setStatus(result.error || '建立失敗', true);
            return;
          }

          window.location.href = '/admin';
        } catch {
          setStatus('建立失敗，請稍後再試', true);
        }
      });
    </script>
  `
  );
}

function renderRootAdminHelp(baseDomain) {
  return renderLayout(
    "Admin",
    `
    <section class="panel">
      <p class="eyebrow">admin gateway</p>
      <h1>請從你的子域名登入</h1>
      <p class="muted">管理地址格式：<code>https://xxx.${escapeHtml(baseDomain)}/admin</code></p>
    </section>
  `
  );
}

function renderSiteHomePage(site, posts, baseDomain) {
  const list = posts.length
    ? posts
        .map(
          (post) => `
          <li class="post-item">
            <a href="/${encodeURIComponent(post.postSlug)}" class="post-link">${escapeHtml(post.title)}</a>
            <p class="muted">${escapeHtml(post.description || "")}</p>
            <small>${escapeHtml(formatDate(post.updatedAt))}</small>
          </li>
        `
        )
        .join("\n")
    : `<p class="muted">還沒有已發佈文章。</p>`;

  return renderLayout(
    site.displayName,
    `
    <section class="panel wide">
      <header class="site-header">
        <div>
          <p class="eyebrow">${escapeHtml(site.slug)}.${escapeHtml(baseDomain)}</p>
          <h1>${escapeHtml(site.displayName)}</h1>
          <p class="muted">${escapeHtml(site.description || "")}</p>
        </div>
        <a class="link-button" href="/admin">Admin</a>
      </header>

      <ul class="post-list">
        ${list}
      </ul>
    </section>
  `
  );
}

function renderPostPage(site, post, articleHtml, baseDomain) {
  return renderLayout(
    `${post.title} - ${site.displayName}`,
    `
    <article class="panel wide article">
      <p class="eyebrow"><a href="/">← ${escapeHtml(site.displayName)}</a> · ${escapeHtml(site.slug)}.${escapeHtml(baseDomain)}</p>
      <h1>${escapeHtml(post.title)}</h1>
      <p class="muted">${escapeHtml(formatDate(post.updatedAt))}</p>
      <div class="article-body">${articleHtml}</div>
    </article>
  `
  );
}

function renderAdminPage(site, authed, baseDomain) {
  if (!authed) {
    return renderLayout(
      `${site.displayName} Admin`,
      `
      <section class="panel">
        <p class="eyebrow">admin</p>
        <h1>${escapeHtml(site.displayName)}</h1>

        <form id="login-form" class="stack" autocomplete="off">
          <label>管理密碼</label>
          <input id="password" type="password" minlength="8" required />
          <button type="submit">登入</button>
        </form>

        <p id="status" class="muted"></p>
      </section>

      <script>
        const form = document.getElementById('login-form');
        const statusEl = document.getElementById('status');

        function setStatus(message, isError = false) {
          statusEl.textContent = message;
          statusEl.style.color = isError ? '#ae3a22' : '#6b6357';
        }

        form.addEventListener('submit', async (event) => {
          event.preventDefault();
          setStatus('登入中...');

          try {
            const response = await fetch('/api/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                slug: ${JSON.stringify(site.slug)},
                password: document.getElementById('password').value,
              }),
            });

            const result = await response.json();
            if (!response.ok) {
              setStatus(result.error || '登入失敗', true);
              return;
            }

            location.reload();
          } catch {
            setStatus('登入失敗，請稍後再試', true);
          }
        });
      </script>
    `
    );
  }

  return renderLayout(
    `${site.displayName} Admin`,
    `
    <section class="panel wide admin-shell">
      <header class="site-header">
        <div>
          <p class="eyebrow">editor</p>
          <h1>${escapeHtml(site.displayName)}</h1>
          <p class="muted">${escapeHtml(site.slug)}.${escapeHtml(baseDomain)}</p>
        </div>
        <div class="row-actions">
          <button id="new-post" class="link-button" type="button">New</button>
          <button id="logout" class="link-button" type="button">Logout</button>
          <a class="link-button" href="/api/export">Export</a>
        </div>
      </header>

      <div class="admin-grid">
        <aside class="admin-list">
          <p class="muted">Posts</p>
          <ul id="post-list"></ul>
        </aside>

        <section class="admin-editor">
          <label>Title</label>
          <input id="title" maxlength="120" />

          <label>Post slug</label>
          <input id="postSlug" maxlength="80" />

          <label>Description</label>
          <input id="description" maxlength="240" />

          <label class="inline-check">
            <input id="published" type="checkbox" />
            Published
          </label>

          <label>Content</label>
          <textarea id="content" placeholder="# Start writing..."></textarea>

          <div class="row-actions">
            <button id="save" type="button">Save (Cmd/Ctrl + S)</button>
            <a id="preview" class="link-button" href="#" target="_blank" rel="noreferrer noopener">Open</a>
          </div>

          <p id="editor-status" class="muted"></p>
        </section>
      </div>
    </section>

    <script>
      const state = {
        currentSlug: '',
        posts: [],
      };

      const postList = document.getElementById('post-list');
      const titleInput = document.getElementById('title');
      const postSlugInput = document.getElementById('postSlug');
      const descriptionInput = document.getElementById('description');
      const publishedInput = document.getElementById('published');
      const contentInput = document.getElementById('content');
      const statusEl = document.getElementById('editor-status');
      const previewLink = document.getElementById('preview');

      function setStatus(message, isError = false) {
        statusEl.textContent = message;
        statusEl.style.color = isError ? '#ae3a22' : '#6b6357';
      }

      function toSlug(value) {
        return String(value || '')
          .toLowerCase()
          .trim()
          .replace(/[^a-z0-9\s-]/g, '')
          .replace(/\s+/g, '-')
          .replace(/-+/g, '-')
          .replace(/^-|-$/g, '')
          .slice(0, 80);
      }

      function syncPreview() {
        const slug = postSlugInput.value.trim().toLowerCase();
        previewLink.href = slug ? '/' + encodeURIComponent(slug) : '#';
      }

      function resetEditor() {
        state.currentSlug = '';
        titleInput.value = '';
        postSlugInput.value = '';
        descriptionInput.value = '';
        publishedInput.checked = false;
        contentInput.value = '';
        syncPreview();
        setStatus('New post');
      }

      function renderPostList() {
        if (!state.posts.length) {
          postList.innerHTML = '<li class="muted">No posts yet</li>';
          return;
        }

        const escapeText = (value) =>
          String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');

        postList.innerHTML = state.posts
          .map((post) => {
            const activeClass = post.postSlug === state.currentSlug ? 'active' : '';
            const stateLabel = Number(post.published) === 1 ? 'Published' : 'Draft';
            return '<li><button class="post-item-btn ' + activeClass + '" data-slug="' +
              post.postSlug + '">' +
              escapeText(post.title) +
              ' <small>(' + stateLabel + ')</small></button></li>';
          })
          .join('');

        Array.from(document.querySelectorAll('.post-item-btn')).forEach((button) => {
          button.addEventListener('click', () => {
            loadPost(button.getAttribute('data-slug'));
          });
        });
      }

      async function fetchJson(path, options) {
        const response = await fetch(path, options);
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.error || 'Request failed');
        }
        return payload;
      }

      async function refreshPosts() {
        const payload = await fetchJson('/api/list-posts?includeDrafts=1');
        state.posts = payload.posts || [];
        renderPostList();
      }

      async function loadPost(slug) {
        if (!slug) {
          return;
        }

        try {
          const payload = await fetchJson('/api/posts/' + encodeURIComponent(slug));
          const post = payload.post;
          state.currentSlug = post.postSlug;
          titleInput.value = post.title || '';
          postSlugInput.value = post.postSlug || '';
          descriptionInput.value = post.description || '';
          publishedInput.checked = Number(post.published) === 1;
          contentInput.value = post.content || '';
          syncPreview();
          renderPostList();
          setStatus('Loaded ' + post.postSlug);
        } catch (error) {
          setStatus(error.message || 'Failed to load post', true);
        }
      }

      async function savePost() {
        const title = titleInput.value.trim();
        const postSlug = (postSlugInput.value.trim() || toSlug(title)).toLowerCase();

        if (!title) {
          setStatus('Title is required', true);
          return;
        }

        if (!postSlug) {
          setStatus('Post slug is required', true);
          return;
        }

        setStatus('Saving...');

        try {
          const payload = await fetchJson('/api/posts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              title,
              postSlug,
              description: descriptionInput.value.trim(),
              content: contentInput.value,
              published: publishedInput.checked,
            }),
          });

          state.currentSlug = payload.post.postSlug;
          postSlugInput.value = payload.post.postSlug;
          syncPreview();
          await refreshPosts();
          setStatus('Saved at ' + new Date().toLocaleTimeString());
        } catch (error) {
          setStatus(error.message || 'Save failed', true);
        }
      }

      document.getElementById('new-post').addEventListener('click', resetEditor);
      document.getElementById('save').addEventListener('click', savePost);
      document.getElementById('logout').addEventListener('click', async () => {
        await fetch('/api/logout', { method: 'POST' });
        location.reload();
      });

      titleInput.addEventListener('blur', () => {
        if (!postSlugInput.value.trim()) {
          postSlugInput.value = toSlug(titleInput.value);
          syncPreview();
        }
      });

      postSlugInput.addEventListener('input', () => {
        postSlugInput.value = toSlug(postSlugInput.value);
        syncPreview();
      });

      document.addEventListener('keydown', (event) => {
        if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 's') {
          event.preventDefault();
          savePost();
        }
      });

      resetEditor();
      refreshPosts().catch((error) => {
        setStatus(error.message || 'Failed to load posts', true);
      });
    </script>
  `
  );
}

function renderSimpleMessage(code, message) {
  return renderLayout(
    `${code}`,
    `
    <section class="panel">
      <p class="eyebrow">${escapeHtml(code)}</p>
      <h1>${escapeHtml(message)}</h1>
      <p class="muted"><a href="/">Back</a></p>
    </section>
  `
  );
}

function renderLayout(title, body) {
  return `<!doctype html>
<html lang="zh-Hant">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      :root {
        --bg-1: #f8f2e9;
        --bg-2: #efe4d6;
        --ink: #2f2b24;
        --muted: #6b6357;
        --panel: rgba(255, 252, 247, 0.88);
        --line: rgba(55, 49, 40, 0.16);
        --accent: #7b5034;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        color: var(--ink);
        font-family: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", serif;
        background:
          radial-gradient(900px 400px at 10% -10%, rgba(150, 106, 64, 0.14), transparent 60%),
          radial-gradient(700px 350px at 100% 0%, rgba(99, 117, 132, 0.08), transparent 55%),
          linear-gradient(160deg, var(--bg-1), var(--bg-2));
        min-height: 100vh;
      }

      main {
        width: min(980px, 92vw);
        margin: 2.8rem auto;
      }

      .panel {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 18px;
        box-shadow: 0 14px 40px rgba(41, 33, 22, 0.08);
        padding: clamp(1.2rem, 3vw, 2rem);
        backdrop-filter: blur(2px);
      }

      .wide {
        width: 100%;
      }

      .eyebrow {
        font-family: "Avenir Next", "Gill Sans", "Trebuchet MS", sans-serif;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--muted);
        font-size: 0.75rem;
        margin: 0;
      }

      h1,
      h2,
      h3,
      h4 {
        margin: 0.35rem 0 0.7rem;
        line-height: 1.2;
      }

      .muted {
        color: var(--muted);
      }

      .stack {
        display: grid;
        gap: 0.6rem;
        margin-top: 1rem;
      }

      label {
        font-family: "Avenir Next", "Gill Sans", "Trebuchet MS", sans-serif;
        font-size: 0.9rem;
      }

      input,
      textarea,
      button,
      .link-button {
        font: inherit;
        border-radius: 10px;
      }

      input,
      textarea {
        border: 1px solid var(--line);
        background: rgba(255, 255, 255, 0.72);
        padding: 0.65rem 0.75rem;
      }

      textarea {
        min-height: 360px;
        resize: vertical;
        line-height: 1.6;
      }

      button,
      .link-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: 0;
        cursor: pointer;
        padding: 0.62rem 0.95rem;
        background: var(--accent);
        color: #f7eee2;
        text-decoration: none;
      }

      button:hover,
      .link-button:hover {
        filter: brightness(1.05);
      }

      .site-header {
        display: flex;
        align-items: start;
        justify-content: space-between;
        gap: 1rem;
        margin-bottom: 1rem;
      }

      .post-list {
        display: grid;
        gap: 0.9rem;
        margin: 1rem 0 0;
        padding: 0;
        list-style: none;
      }

      .post-item {
        border-bottom: 1px dashed var(--line);
        padding-bottom: 0.7rem;
      }

      .post-link {
        text-decoration: none;
        color: var(--ink);
        font-size: 1.2rem;
      }

      .article-body {
        line-height: 1.7;
      }

      .article-body pre {
        background: rgba(47, 43, 36, 0.95);
        color: #f8f5ee;
        padding: 0.9rem;
        border-radius: 10px;
        overflow-x: auto;
      }

      .article-body code {
        background: rgba(90, 82, 69, 0.13);
        padding: 0.1rem 0.3rem;
        border-radius: 5px;
      }

      .admin-shell {
        display: grid;
        gap: 1rem;
      }

      .admin-grid {
        display: grid;
        grid-template-columns: 260px 1fr;
        gap: 1rem;
      }

      .admin-list {
        border-right: 1px solid var(--line);
        padding-right: 0.9rem;
      }

      .admin-list ul {
        list-style: none;
        margin: 0;
        padding: 0;
        display: grid;
        gap: 0.45rem;
      }

      .post-item-btn {
        width: 100%;
        text-align: left;
        background: rgba(255, 255, 255, 0.65);
        color: var(--ink);
        border: 1px solid var(--line);
      }

      .post-item-btn.active {
        border-color: var(--accent);
        background: rgba(123, 80, 52, 0.12);
      }

      .admin-editor {
        display: grid;
        gap: 0.5rem;
      }

      .row-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
      }

      .inline-check {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        margin: 0.4rem 0;
      }

      a {
        color: var(--accent);
      }

      code {
        font-family: "SFMono-Regular", Menlo, Consolas, monospace;
      }

      @media (max-width: 860px) {
        main {
          margin-top: 1.2rem;
        }

        .admin-grid {
          grid-template-columns: 1fr;
        }

        .admin-list {
          border-right: 0;
          border-bottom: 1px solid var(--line);
          padding-right: 0;
          padding-bottom: 0.9rem;
        }

        textarea {
          min-height: 280px;
        }
      }
    </style>
  </head>
  <body>
    <main>
      ${body}
    </main>
  </body>
</html>`;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }

  return date.toLocaleString("zh-Hant", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function buildWelcomePost(slug, displayName, baseDomain) {
  return `# Welcome to ${displayName}\n\n你已成功建立站點：\`${slug}.${baseDomain}\`。\n\n- 前台首頁：https://${slug}.${baseDomain}\n- 後台編輯：https://${slug}.${baseDomain}/admin\n\n現在你可以直接在後台開始寫作，體驗會偏向 Bear 的簡潔流。\n`;
}

function renderMarkdown(source) {
  const lines = String(source || "").replace(/\r\n/g, "\n").split("\n");

  const blocks = [];
  let paragraph = [];
  let listItems = [];
  let codeBlock = null;

  const flushParagraph = () => {
    if (!paragraph.length) {
      return;
    }
    const text = paragraph.join(" ");
    blocks.push(`<p>${renderInline(text)}</p>`);
    paragraph = [];
  };

  const flushList = () => {
    if (!listItems.length) {
      return;
    }
    blocks.push(`<ul>${listItems.map((item) => `<li>${renderInline(item)}</li>`).join("")}</ul>`);
    listItems = [];
  };

  const flushCode = () => {
    if (!codeBlock) {
      return;
    }
    blocks.push(`<pre><code>${escapeHtml(codeBlock.join("\n"))}</code></pre>`);
    codeBlock = null;
  };

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      flushParagraph();
      flushList();

      if (codeBlock) {
        flushCode();
      } else {
        codeBlock = [];
      }

      continue;
    }

    if (codeBlock) {
      codeBlock.push(line);
      continue;
    }

    if (!line.trim()) {
      flushParagraph();
      flushList();
      continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      flushParagraph();
      flushList();
      const level = heading[1].length;
      blocks.push(`<h${level}>${renderInline(heading[2])}</h${level}>`);
      continue;
    }

    const listItem = line.match(/^\s*[-*]\s+(.+)$/);
    if (listItem) {
      flushParagraph();
      listItems.push(listItem[1]);
      continue;
    }

    const quote = line.match(/^>\s?(.*)$/);
    if (quote) {
      flushParagraph();
      flushList();
      blocks.push(`<blockquote>${renderInline(quote[1])}</blockquote>`);
      continue;
    }

    paragraph.push(line.trim());
  }

  flushParagraph();
  flushList();
  flushCode();

  return blocks.join("\n");
}

function renderInline(value) {
  let text = escapeHtml(value);

  text = text.replace(/`([^`]+)`/g, "<code>$1</code>");
  text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/\*([^*]+)\*/g, "<em>$1</em>");

  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (match, label, url) => {
    const rawUrl = String(url || "").trim();
    if (!/^https?:\/\//i.test(rawUrl)) {
      return `${label} (${escapeHtml(rawUrl)})`;
    }

    const safeUrl = escapeHtml(rawUrl);
    return `<a href="${safeUrl}" target="_blank" rel="noreferrer noopener">${label}</a>`;
  });

  return text;
}
