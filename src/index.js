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
const DEFAULT_API_ENTRY_SLUG = "app";
const SITE_CONFIG_VERSION = 2;

const LOGIN_RATE_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_RATE_MAX_ATTEMPTS = 5;
const loginAttempts = new Map();

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
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

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = normalizePath(url.pathname);
  const hostHeader = request.headers.get("host") || url.host;
  const hostname = hostHeader.split(":")[0].toLowerCase();
  const baseDomain = String(env.BASE_DOMAIN || "bdfz.net").toLowerCase();
  const apiEntrySlug = String(env.API_ENTRY_SLUG || DEFAULT_API_ENTRY_SLUG)
    .trim()
    .toLowerCase();
  const hostSlug = getHostSlug(hostname, baseDomain);
  const reservedSlugs = getReservedSlugs(env);

  if (path === "/healthz") {
    return text("ok");
  }

  if (path.startsWith("/api/")) {
    if (request.method === "OPTIONS") {
      return buildApiPreflightResponse(request, env);
    }

    const response = await handleApi(request, env, ctx, {
      path,
      url,
      hostSlug,
      baseDomain,
      reservedSlugs,
      apiEntrySlug,
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

  if (reservedSlugs.has(hostSlug) && hostSlug !== apiEntrySlug) {
    // Reserved slugs are owned by platform/system services.
    // Let Cloudflare continue to the configured origin for those hosts.
    return fetch(request);
  }

  if (hostSlug === apiEntrySlug && path === "/") {
    return html(renderRootPage(baseDomain), 200);
  }

  if (hostSlug === apiEntrySlug && path === "/admin") {
    return html(renderRootAdminHelp(baseDomain), 200);
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
    const siteConfig = await getSiteConfig(env, site);
    return html(renderAdminPage(site, siteConfig, authed, baseDomain), 200);
  }

  if (path === "/") {
    const posts = await listPosts(env, site.id, false);
    const siteConfig = await getSiteConfig(env, site);
    const communitySites = await listCommunitySites(env, site.slug, 12);
    const campusFeed = await listCampusFeed(env, site.id, 18);
    return html(
      renderSiteHomePage(site, siteConfig, posts, communitySites, campusFeed, baseDomain),
      200
    );
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

  const siteConfig = await getSiteConfig(env, site);
  const communitySites = await listCommunitySites(env, site.slug, 8);
  const articleHtml = renderMarkdown(file.content);
  return html(renderPostPage(site, siteConfig, post, articleHtml, communitySites, baseDomain), 200);
}

async function handleApi(request, env, ctx, context) {
  const { path, url, hostSlug, baseDomain, reservedSlugs, apiEntrySlug } = context;

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

  if (request.method === "GET" && path === "/api/public-sites") {
    const sites = await listPublicSites(env, 1000);
    return json(
      {
        generatedAt: new Date().toISOString(),
        total: sites.length,
        sites,
      },
      200
    );
  }

  if (request.method === "GET" && path === "/api/public-feed") {
    const feed = await listCampusFeed(env, null, 80);
    return json(
      {
        generatedAt: new Date().toISOString(),
        total: feed.length,
        posts: feed,
      },
      200
    );
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

    if (hostSlug && hostSlug !== apiEntrySlug && !reservedSlugs.has(hostSlug) && slug !== hostSlug) {
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
        normalizeSiteConfig(
          {
            slug,
            displayName,
            description,
            heroTitle: "",
            heroSubtitle: "",
            accentColor: "#7b5034",
            footerNote: "在這裡，把語文寫成你自己。",
            headerLinks: [],
            createdAt: now,
            updatedAt: now,
            exportVersion: SITE_CONFIG_VERSION,
          },
          {
            slug,
            displayName,
            description,
            createdAt: now,
            updatedAt: now,
          }
        ),
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

      const notifyTask = notifyTelegramNewSite(env, {
        slug,
        displayName,
        siteUrl: `https://${slug}.${baseDomain}`,
        createdAt: now,
      }).catch((error) => {
        console.error("Telegram notify failed", error);
      });

      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(notifyTask);
      } else {
        await notifyTask;
      }
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

  if (request.method === "GET" && path === "/api/site-settings") {
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

    const config = await getSiteConfig(env, site);
    return json({ site: formatSiteForClient(site), config }, 200);
  }

  if (request.method === "POST" && path === "/api/site-settings") {
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
    const now = new Date().toISOString();

    const displayName = sanitizeName(body.displayName || site.displayName) || site.slug;
    const description = sanitizeDescription(body.description || "");
    const heroTitle = sanitizeTitle(body.heroTitle || "");
    const heroSubtitle = sanitizeDescription(body.heroSubtitle || "");
    const accentColor = sanitizeHexColor(body.accentColor || "#7b5034");
    const footerNote = sanitizeDescription(body.footerNote || "");
    const headerLinks = sanitizeHeaderLinks(body.headerLinks);

    const nextConfig = normalizeSiteConfig(
      {
        slug: site.slug,
        displayName,
        description,
        heroTitle,
        heroSubtitle,
        accentColor,
        footerNote,
        headerLinks,
        createdAt: site.createdAt,
        updatedAt: now,
      },
      site
    );

    try {
      await env.DB.prepare(
        `UPDATE sites
         SET display_name = ?, description = ?, updated_at = ?
         WHERE id = ?`
      )
        .bind(displayName, description, now, site.id)
        .run();

      await githubWriteFile(
        env,
        getSiteConfigPath(site.slug),
        `${JSON.stringify(nextConfig, null, 2)}\n`,
        `feat(${site.slug}): update site settings`
      );
    } catch (error) {
      console.error("Failed to save site settings", error);
      return json(
        {
          error: "Failed to save site settings",
          detail: String(error && error.message ? error.message : error),
        },
        502
      );
    }

    const updatedSite = await getSiteBySlug(env, site.slug);
    return json(
      {
        ok: true,
        site: formatSiteForClient(updatedSite || site),
        config: nextConfig,
      },
      200
    );
  }

  if (request.method === "POST" && path === "/api/login") {
    if (!hostSlug) {
      return json({ error: "Login must happen on site subdomain" }, 400);
    }

    const clientIp = request.headers.get("cf-connecting-ip") || "unknown";
    const rateKey = `${clientIp}:${hostSlug}`;
    const now = Date.now();
    const attempts = loginAttempts.get(rateKey) || [];
    const recent = attempts.filter((t) => now - t < LOGIN_RATE_WINDOW_MS);
    if (recent.length >= LOGIN_RATE_MAX_ATTEMPTS) {
      return json({ error: "Too many login attempts, please try later" }, 429);
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
      recent.push(now);
      loginAttempts.set(rateKey, recent);
      return json({ error: "Invalid credentials" }, 401);
    }

    loginAttempts.delete(rateKey);
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
    const config = await getSiteConfig(env, site);
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
      config,
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

  if (request.method === "POST" && path === "/api/import") {
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

    let formData;
    try {
      formData = await request.formData();
    } catch {
      return json({ error: "Invalid form data" }, 400);
    }

    const file = formData.get("file");
    if (!file || typeof file.text !== "function") {
      return json({ error: "No file uploaded" }, 400);
    }

    let csvText;
    try {
      csvText = await file.text();
    } catch {
      return json({ error: "Failed to read file" }, 400);
    }

    if (!csvText || csvText.length < 10) {
      return json({ error: "File is empty or too small" }, 400);
    }

    if (csvText.length > 10 * 1024 * 1024) {
      return json({ error: "File too large (max 10MB)" }, 400);
    }

    const parsed = parseCSV(csvText);
    if (!parsed.headers.length || !parsed.rows.length) {
      return json({ error: "No valid rows found in CSV" }, 400);
    }

    const imported = [];
    const skipped = [];
    const errors = [];

    for (const row of parsed.rows) {
      try {
        const title = String(row.title || "").trim();
        if (!title) {
          skipped.push({ reason: "missing title" });
          continue;
        }

        if (String(row.is_page || "").toLowerCase() === "true") {
          skipped.push({ title, reason: "is_page" });
          continue;
        }

        let rawSlug = String(row.slug || row.link || "").trim();
        rawSlug = rawSlug.replace(/^\/+/, "");
        let postSlug = rawSlug ? slugifyValue(rawSlug) : slugifyValue(title);
        if (!postSlug) {
          postSlug = slugifyValue(title);
        }
        if (!postSlug) {
          skipped.push({ title, reason: "cannot derive slug" });
          continue;
        }

        const slugCheck = validatePostSlug(postSlug);
        if (!slugCheck.ok) {
          postSlug = slugifyValue(title);
          const recheck = validatePostSlug(postSlug);
          if (!recheck.ok) {
            skipped.push({ title, reason: "invalid slug" });
            continue;
          }
          postSlug = recheck.slug;
        } else {
          postSlug = slugCheck.slug;
        }

        const content = String(row.content || "").trim();
        const description = String(row.meta_description || "").trim().slice(0, 240);

        let publishedDate = String(row.published_date || "").trim();
        let createdAt;
        if (publishedDate) {
          const d = new Date(publishedDate);
          createdAt = Number.isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
        } else {
          createdAt = new Date().toISOString();
        }

        const discoverable = String(row.make_discoverable || "true").toLowerCase();
        const published = discoverable === "false" ? 0 : 1;

        await githubWriteFile(
          env,
          getPostFilePath(site.slug, postSlug),
          content || `# ${title}\n`,
          `import(${site.slug}): ${postSlug} from BearBlog`
        );

        await upsertPostMeta(
          env,
          site.id,
          postSlug,
          sanitizeTitle(title),
          sanitizeDescription(description),
          published,
          createdAt,
          createdAt
        );

        imported.push({ title, postSlug });
      } catch (error) {
        errors.push({ title: row.title || "unknown", error: error.message || "unknown error" });
      }
    }

    return json({
      ok: true,
      imported: imported.length,
      skipped: skipped.length,
      errors: errors.length,
      details: { imported, skipped, errors },
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

function formatSiteForClient(site) {
  if (!site) {
    return null;
  }

  return {
    id: site.id,
    slug: site.slug,
    displayName: site.displayName,
    description: site.description,
    createdAt: site.createdAt,
    updatedAt: site.updatedAt,
    url: `https://${site.slug}.bdfz.net`,
  };
}

async function listPublicSites(env, limit = 500) {
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 1000);
  const result = await env.DB.prepare(
    `SELECT
      s.slug AS slug,
      s.display_name AS displayName,
      s.description AS description,
      s.created_at AS createdAt,
      s.updated_at AS updatedAt,
      (
        SELECT COUNT(*)
        FROM posts p
        WHERE p.site_id = s.id AND p.published = 1
      ) AS postCount
    FROM sites s
    ORDER BY s.created_at DESC
    LIMIT ?`
  )
    .bind(safeLimit)
    .all();

  const rows = result.results || [];
  return rows.map((site) => ({
    slug: site.slug,
    displayName: site.displayName,
    description: site.description || "",
    createdAt: site.createdAt,
    updatedAt: site.updatedAt,
    postCount: Number(site.postCount || 0),
    url: `https://${site.slug}.bdfz.net`,
  }));
}

async function listCommunitySites(env, currentSlug, limit = 12) {
  const safeLimit = Math.min(Math.max(Number(limit) || 12, 1), 60);
  const result = await env.DB.prepare(
    `SELECT
      slug,
      display_name AS displayName,
      description,
      created_at AS createdAt
    FROM sites
    WHERE slug != ?
    ORDER BY created_at DESC
    LIMIT ?`
  )
    .bind(currentSlug, safeLimit)
    .all();

  const rows = result.results || [];
  return rows.map((site) => ({
    slug: site.slug,
    displayName: site.displayName,
    description: site.description || "",
    createdAt: site.createdAt,
    url: `https://${site.slug}.bdfz.net`,
  }));
}

async function listCampusFeed(env, excludeSiteId = null, limit = 24) {
  const safeLimit = Math.min(Math.max(Number(limit) || 24, 1), 120);
  const sql = excludeSiteId
    ? `SELECT
        p.post_slug AS postSlug,
        p.title AS title,
        p.description AS description,
        p.updated_at AS updatedAt,
        s.slug AS siteSlug,
        s.display_name AS siteName
      FROM posts p
      INNER JOIN sites s ON p.site_id = s.id
      WHERE p.published = 1 AND p.site_id != ?
      ORDER BY p.updated_at DESC
      LIMIT ?`
    : `SELECT
        p.post_slug AS postSlug,
        p.title AS title,
        p.description AS description,
        p.updated_at AS updatedAt,
        s.slug AS siteSlug,
        s.display_name AS siteName
      FROM posts p
      INNER JOIN sites s ON p.site_id = s.id
      WHERE p.published = 1
      ORDER BY p.updated_at DESC
      LIMIT ?`;

  const statement = excludeSiteId
    ? env.DB.prepare(sql).bind(excludeSiteId, safeLimit)
    : env.DB.prepare(sql).bind(safeLimit);
  const result = await statement.all();
  const rows = result.results || [];

  return rows.map((post) => ({
    siteSlug: post.siteSlug,
    siteName: post.siteName,
    postSlug: post.postSlug,
    title: post.title,
    description: post.description || "",
    updatedAt: post.updatedAt,
    url: `https://${post.siteSlug}.bdfz.net/${post.postSlug}`,
  }));
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

function defaultSiteConfigFromSite(site) {
  return normalizeSiteConfig(
    {
      slug: site.slug,
      displayName: site.displayName,
      description: site.description || "",
      heroTitle: "",
      heroSubtitle: "",
      accentColor: "#7b5034",
      footerNote: "在這裡，把語文寫成你自己。",
      headerLinks: [],
      createdAt: site.createdAt || new Date().toISOString(),
      updatedAt: site.updatedAt || new Date().toISOString(),
      exportVersion: SITE_CONFIG_VERSION,
    },
    site
  );
}

function sanitizeHexColor(value) {
  const raw = String(value || "")
    .trim()
    .toLowerCase();

  if (/^#[0-9a-f]{6}$/.test(raw)) {
    return raw;
  }

  if (/^#[0-9a-f]{3}$/.test(raw)) {
    return `#${raw[1]}${raw[1]}${raw[2]}${raw[2]}${raw[3]}${raw[3]}`;
  }

  return "#7b5034";
}

function sanitizeHeaderLinks(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .slice(0, 8)
    .map((item) => ({
      label: sanitizeName(item?.label || "").slice(0, 24),
      url: sanitizeUrl(item?.url || ""),
    }))
    .filter((item) => item.label && item.url);
}

function sanitizeUrl(value) {
  const url = String(value || "").trim();
  if (!url) {
    return "";
  }

  if (/^https?:\/\//i.test(url)) {
    return url.slice(0, 240);
  }

  return "";
}

function normalizeSiteConfig(rawConfig, site) {
  const base = site
    ? defaultSiteConfigFromSiteBase(site)
    : {
      slug: "",
      displayName: "",
      description: "",
      heroTitle: "",
      heroSubtitle: "",
      accentColor: "#7b5034",
      footerNote: "在這裡，把語文寫成你自己。",
      headerLinks: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      exportVersion: SITE_CONFIG_VERSION,
    };

  const merged = {
    ...base,
    ...(rawConfig && typeof rawConfig === "object" ? rawConfig : {}),
  };

  return {
    slug: String(merged.slug || base.slug).toLowerCase(),
    displayName: sanitizeName(merged.displayName || base.displayName) || base.slug,
    description: sanitizeDescription(merged.description || ""),
    heroTitle: sanitizeTitle(merged.heroTitle || ""),
    heroSubtitle: sanitizeDescription(merged.heroSubtitle || ""),
    accentColor: sanitizeHexColor(merged.accentColor || base.accentColor),
    footerNote: sanitizeDescription(merged.footerNote || base.footerNote),
    headerLinks: sanitizeHeaderLinks(Array.isArray(merged.headerLinks) ? merged.headerLinks : []),
    createdAt: String(merged.createdAt || base.createdAt),
    updatedAt: String(merged.updatedAt || new Date().toISOString()),
    exportVersion: SITE_CONFIG_VERSION,
  };
}

function defaultSiteConfigFromSiteBase(site) {
  return {
    slug: site.slug,
    displayName: site.displayName || site.slug,
    description: site.description || "",
    heroTitle: "",
    heroSubtitle: "",
    accentColor: "#7b5034",
    footerNote: "在這裡，把語文寫成你自己。",
    headerLinks: [],
    createdAt: site.createdAt || new Date().toISOString(),
    updatedAt: site.updatedAt || new Date().toISOString(),
    exportVersion: SITE_CONFIG_VERSION,
  };
}

async function getSiteConfig(env, site) {
  const fallback = defaultSiteConfigFromSite(site);
  const filePath = getSiteConfigPath(site.slug);

  try {
    const file = await githubReadFile(env, filePath);
    if (!file || !file.content) {
      return fallback;
    }

    const parsed = JSON.parse(file.content);
    return normalizeSiteConfig(parsed, site);
  } catch (error) {
    console.error("Failed to load site config", error);
    return fallback;
  }
}

async function notifyTelegramNewSite(env, payload) {
  const botToken = String(env.TELEGRAM_BOT_TOKEN || "").trim();
  const chatId = String(env.TELEGRAM_CHAT_ID || "").trim();

  if (!botToken || !chatId) {
    return;
  }

  const lines = [
    "🆕 新 Blog 註冊",
    `站點：${payload.slug}.bdfz.net`,
    `名稱：${payload.displayName}`,
    `時間：${payload.createdAt}`,
    `後台：${payload.siteUrl}/admin`,
  ];

  const endpoint = `https://api.telegram.org/bot${botToken}/sendMessage`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      chat_id: chatId,
      text: lines.join("\n"),
      disable_web_page_preview: true,
    }),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Telegram notify failed: ${response.status} ${detail}`);
  }
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

function parseCSV(text) {
  const lines = String(text || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const result = { headers: [], rows: [] };
  let i = 0;
  const len = lines.length;

  function parseField() {
    if (i >= len || lines[i] === "\n") return "";
    if (lines[i] === '"') {
      i++;
      let val = "";
      while (i < len) {
        if (lines[i] === '"') {
          if (i + 1 < len && lines[i + 1] === '"') {
            val += '"';
            i += 2;
          } else {
            i++;
            break;
          }
        } else {
          val += lines[i];
          i++;
        }
      }
      return val;
    }
    let val = "";
    while (i < len && lines[i] !== "," && lines[i] !== "\n") {
      val += lines[i];
      i++;
    }
    return val;
  }

  function parseRow() {
    const fields = [];
    while (i < len && lines[i] !== "\n") {
      fields.push(parseField());
      if (i < len && lines[i] === ",") i++;
    }
    if (i < len && lines[i] === "\n") i++;
    return fields;
  }

  if (len === 0) return result;

  result.headers = parseRow().map((h) => h.trim().toLowerCase().replace(/\s+/g, "_"));
  if (!result.headers.length) return result;

  while (i < len) {
    if (lines[i] === "\n") { i++; continue; }
    const fields = parseRow();
    if (fields.length === 0 || (fields.length === 1 && !fields[0])) continue;
    const obj = {};
    for (let j = 0; j < result.headers.length; j++) {
      obj[result.headers[j]] = j < fields.length ? fields[j] : "";
    }
    result.rows.push(obj);
  }

  return result;
}

const MAX_BODY_BYTES = 65536;

async function readJson(request) {
  try {
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > MAX_BODY_BYTES) {
      throw new Error("Request body too large");
    }
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) {
      throw new Error("Request body too large");
    }
    return JSON.parse(text);
  } catch (error) {
    if (error && error.message === "Request body too large") {
      throw error;
    }
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
      "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https:; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
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
      <h1>所謂語文，無非你寫。</h1>
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

function renderSiteHomePage(site, siteConfig, posts, communitySites, campusFeed, baseDomain) {
  const heading = siteConfig.heroTitle || site.displayName;
  const subtitle = siteConfig.heroSubtitle || site.description || "";
  const accentStyle = `--accent:${escapeHtml(siteConfig.accentColor)};`;

  const navLinks = (siteConfig.headerLinks || []).length
    ? `<nav class="site-nav">${siteConfig.headerLinks
      .map(
        (item) =>
          `<a href="${escapeHtml(item.url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(
            item.label
          )}</a>`
      )
      .join("")}</nav>`
    : "";

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

  const peerSites = communitySites.length
    ? communitySites
      .map(
        (peer) =>
          `<li><a href="${escapeHtml(peer.url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(
            peer.displayName
          )}</a><span class="muted"> · ${escapeHtml(peer.slug)}.bdfz.net</span></li>`
      )
      .join("")
    : `<li class="muted">暫時沒有其他同學站點。</li>`;

  const feedItems = campusFeed.length
    ? campusFeed
      .map(
        (entry) =>
          `<li><a href="${escapeHtml(entry.url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(
            entry.title
          )}</a><span class="muted"> · ${escapeHtml(entry.siteName)}</span></li>`
      )
      .join("")
    : `<li class="muted">全校文章流暫時為空。</li>`;

  return renderLayout(
    site.displayName,
    `
    <section class="panel wide site-home-shell" style="${accentStyle}">
      <header class="site-header">
        <div>
          <p class="eyebrow">${escapeHtml(site.slug)}.${escapeHtml(baseDomain)}</p>
          <h1>${escapeHtml(heading)}</h1>
          <p class="muted">${escapeHtml(subtitle)}</p>
        </div>
        <div class="row-actions">
          <a class="link-button" href="/admin">Admin</a>
        </div>
      </header>
      ${navLinks}

      <div class="community-grid">
        <section>
          <h2>文章</h2>
          <ul class="post-list">
            ${list}
          </ul>
        </section>
        <aside class="community-panel">
          <h3>同學新站</h3>
          <ul class="mini-list">${peerSites}</ul>
          <h3>全校最新文章</h3>
          <ul class="mini-list">${feedItems}</ul>
        </aside>
      </div>

      <footer class="site-footer muted">${escapeHtml(
      siteConfig.footerNote || "在這裡，把語文寫成你自己。"
    )}</footer>
    </section>
  `
  );
}

function renderPostPage(site, siteConfig, post, articleHtml, communitySites, baseDomain) {
  const peerSites = communitySites.length
    ? communitySites
      .map(
        (peer) =>
          `<li><a href="${escapeHtml(peer.url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(
            peer.displayName
          )}</a></li>`
      )
      .join("")
    : `<li class="muted">暫時沒有其他同學站點。</li>`;

  // Estimate read time (~400 chars/min for Chinese)
  const charCount = articleHtml.replace(/<[^>]+>/g, "").length;
  const readMinutes = Math.max(1, Math.round(charCount / 400));

  return renderLayout(
    `${post.title} - ${site.displayName}`,
    `
    <div class="reading-progress" id="reading-progress"></div>
    <section class="panel wide article-wrap" style="--accent:${escapeHtml(siteConfig.accentColor)};">
      <article class="article">
        <p class="eyebrow"><a href="/">← ${escapeHtml(site.displayName)}</a> · ${escapeHtml(
      site.slug
    )}.${escapeHtml(baseDomain)}</p>
        <h1>${escapeHtml(post.title)}</h1>
        <p class="muted">${escapeHtml(formatDate(post.updatedAt))} <span class="read-time">· ${readMinutes} min read</span></p>
        <div class="article-body">${articleHtml}</div>
      </article>
      <aside class="article-side">
        <h3>同學站點</h3>
        <ul class="mini-list">${peerSites}</ul>
      </aside>
    </section>
    <button class="back-top" id="back-top" aria-label="Back to top">↑</button>
    <script>
      (function() {
        const progress = document.getElementById('reading-progress');
        const backTop = document.getElementById('back-top');
        function onScroll() {
          const scrollTop = window.scrollY;
          const docHeight = document.documentElement.scrollHeight - window.innerHeight;
          if (docHeight > 0 && progress) {
            progress.style.width = Math.min(100, (scrollTop / docHeight) * 100) + '%';
          }
          if (backTop) {
            backTop.classList.toggle('visible', scrollTop > 400);
          }
        }
        window.addEventListener('scroll', onScroll, { passive: true });
        if (backTop) {
          backTop.addEventListener('click', function() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
          });
        }
      })();
    </script>
  `
  );
}

function renderAdminPage(site, siteConfig, authed, baseDomain) {
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
    <section class="panel wide admin-shell" style="--accent:${escapeHtml(siteConfig.accentColor)};">
      <header class="site-header">
        <div>
          <p class="eyebrow">editor</p>
          <h1>${escapeHtml(siteConfig.heroTitle || site.displayName)}</h1>
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
          <button id="settings-toggle" class="settings-toggle" type="button">▸ Site Settings</button>
          <div id="settings-section" class="settings-section">
            <p class="muted">Site Settings</p>
            <label>顯示名稱</label>
            <input id="siteDisplayName" maxlength="60" />
            <label>站點簡介</label>
            <input id="siteDescription" maxlength="240" />
            <label>首頁標題</label>
            <input id="siteHeroTitle" maxlength="120" />
            <label>首頁副標</label>
            <input id="siteHeroSubtitle" maxlength="240" />
            <label>主色</label>
            <input id="siteAccentColor" maxlength="7" placeholder="#7b5034" />
            <label>頁尾文字</label>
            <input id="siteFooterNote" maxlength="240" />
            <label>外部連結（每行：標題|https://url）</label>
            <textarea id="siteHeaderLinks" class="small-textarea" placeholder="作品集|https://example.com"></textarea>
            <button id="save-settings" type="button">儲存站點設定</button>
          </div>

          <p class="muted">Posts</p>
          <ul id="post-list"></ul>

          <p class="muted" style="margin-top:0.8rem">Import</p>
          <label>從 BearBlog 匯入 CSV</label>
          <input id="import-file" type="file" accept=".csv" />
          <button id="import-btn" type="button">匯入</button>
          <p id="import-status" class="muted"></p>
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
          <div class="md-toolbar">
            <button type="button" data-md="bold" title="Bold">B</button>
            <button type="button" data-md="italic" title="Italic">I</button>
            <button type="button" data-md="code" title="Code">&#96;</button>
            <button type="button" data-md="heading" title="Heading">H</button>
            <button type="button" data-md="link" title="Link">🔗</button>
            <button type="button" data-md="list" title="List">•</button>
            <button type="button" id="fullscreen-toggle" class="fullscreen-btn">⛶ 全屏</button>
          </div >
          <textarea id="content" placeholder="# Start writing..."></textarea>

          <div class="row-actions">
            <button id="save" type="button">Save (⌘/Ctrl + S)</button>
            <a id="preview" class="link-button" href="#" target="_blank" rel="noreferrer noopener">Open</a>
          </div>

          <p id="editor-status" class="muted"></p>
        </section >
      </div >
    </section >

    <script>
      const initialConfig = ${toScriptJson(siteConfig)};
      const state = {
        currentSlug: '',
      posts: [],
      siteConfig: initialConfig,
      };

      const postList = document.getElementById('post-list');
      const siteDisplayNameInput = document.getElementById('siteDisplayName');
      const siteDescriptionInput = document.getElementById('siteDescription');
      const siteHeroTitleInput = document.getElementById('siteHeroTitle');
      const siteHeroSubtitleInput = document.getElementById('siteHeroSubtitle');
      const siteAccentColorInput = document.getElementById('siteAccentColor');
      const siteFooterNoteInput = document.getElementById('siteFooterNote');
      const siteHeaderLinksInput = document.getElementById('siteHeaderLinks');
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

      function normalizeHexColor(value) {
        const raw = String(value || '').trim().toLowerCase();
      if (/^#[0-9a-f]{6}$/.test(raw)) {
          return raw;
        }
      if (/^#[0-9a-f]{3}$/.test(raw)) {
          return '#' + raw[1] + raw[1] + raw[2] + raw[2] + raw[3] + raw[3];
        }
      return '#7b5034';
      }

      function escapeText(value) {
        return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseHeaderLinks(raw) {
  return String(raw || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 8)
    .map((line) => {
      const [label, url] = line.split('|').map((item) => item.trim());
      if (!label || !url || !/^https?:\/\//i.test(url)) {
        return null;
      }
      return { label: label.slice(0, 24), url: url.slice(0, 240) };
    })
    .filter(Boolean);
}

function renderHeaderLinksValue(links) {
  return (links || [])
    .map((item) => item.label + '|' + item.url)
    .join('\n');
}

function applySettingsToForm(config) {
  const safe = config || {};
  siteDisplayNameInput.value = safe.displayName || '';
  siteDescriptionInput.value = safe.description || '';
  siteHeroTitleInput.value = safe.heroTitle || '';
  siteHeroSubtitleInput.value = safe.heroSubtitle || '';
  siteAccentColorInput.value = normalizeHexColor(safe.accentColor || '#7b5034');
  siteFooterNoteInput.value = safe.footerNote || '';
  siteHeaderLinksInput.value = renderHeaderLinksValue(safe.headerLinks || []);
}

function draftKey(slug) {
  const id = slug || 'new';
  return 'stublogs-draft:' + location.host + ':' + id;
}

function saveDraft() {
  const key = draftKey(state.currentSlug);
  const payload = {
    title: titleInput.value,
    postSlug: postSlugInput.value,
    description: descriptionInput.value,
    content: contentInput.value,
    published: publishedInput.checked,
    savedAt: Date.now(),
  };

  try {
    localStorage.setItem(key, JSON.stringify(payload));
  } catch {
    // ignore localStorage quota errors
  }
}

function tryRestoreDraft(slug) {
  const key = draftKey(slug);
  try {
    const raw = localStorage.getItem(key);
    if (!raw) {
      return;
    }
    const draft = JSON.parse(raw);
    if (!draft || !draft.content) {
      return;
    }

    if (!contentInput.value.trim()) {
      titleInput.value = draft.title || titleInput.value;
      postSlugInput.value = draft.postSlug || postSlugInput.value;
      descriptionInput.value = draft.description || descriptionInput.value;
      contentInput.value = draft.content || contentInput.value;
      publishedInput.checked = Boolean(draft.published);
      syncPreview();
    }
  } catch {
    // ignore malformed drafts
  }
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
  tryRestoreDraft('');
}

function renderPostList() {
  if (!state.posts.length) {
    postList.innerHTML = '<li class="muted">No posts yet</li>';
    return;
  }

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

async function refreshSettings() {
  const payload = await fetchJson('/api/site-settings');
  state.siteConfig = payload.config || state.siteConfig;
  applySettingsToForm(state.siteConfig);
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
    tryRestoreDraft(post.postSlug);
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
    saveDraft();
  } catch (error) {
    setStatus(error.message || 'Save failed', true);
  }
}

async function saveSiteSettings() {
  setStatus('Saving site settings...');
  try {
    const payload = await fetchJson('/api/site-settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        displayName: siteDisplayNameInput.value.trim(),
        description: siteDescriptionInput.value.trim(),
        heroTitle: siteHeroTitleInput.value.trim(),
        heroSubtitle: siteHeroSubtitleInput.value.trim(),
        accentColor: normalizeHexColor(siteAccentColorInput.value),
        footerNote: siteFooterNoteInput.value.trim(),
        headerLinks: parseHeaderLinks(siteHeaderLinksInput.value),
      }),
    });

    state.siteConfig = payload.config || state.siteConfig;
    applySettingsToForm(state.siteConfig);
    document.documentElement.style.setProperty('--accent', state.siteConfig.accentColor || '#7b5034');
    setStatus('Site settings saved');
  } catch (error) {
    setStatus(error.message || 'Failed to save site settings', true);
  }
}

document.getElementById('new-post').addEventListener('click', resetEditor);
document.getElementById('save').addEventListener('click', savePost);
document.getElementById('save-settings').addEventListener('click', saveSiteSettings);
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

contentInput.addEventListener('input', saveDraft);
titleInput.addEventListener('input', saveDraft);
descriptionInput.addEventListener('input', saveDraft);
publishedInput.addEventListener('change', saveDraft);

document.addEventListener('keydown', (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 's') {
    event.preventDefault();
    if (event.shiftKey) {
      saveSiteSettings();
    } else {
      savePost();
    }
  }
});

applySettingsToForm(initialConfig);
resetEditor();
refreshSettings().catch((error) => {
  setStatus(error.message || 'Failed to load site settings', true);
});
refreshPosts().catch((error) => {
  setStatus(error.message || 'Failed to load posts', true);
});

// ── Settings toggle (mobile) ──
const settingsToggle = document.getElementById('settings-toggle');
const settingsSection = document.getElementById('settings-section');
if (settingsToggle && settingsSection) {
  if (window.innerWidth <= 860) {
    settingsSection.classList.add('collapsed');
  }
  settingsToggle.addEventListener('click', () => {
    const collapsed = settingsSection.classList.toggle('collapsed');
    settingsToggle.textContent = (collapsed ? '▸' : '▾') + ' Site Settings';
  });
}

// ── Markdown toolbar ──
function insertMd(type) {
  const ta = contentInput;
  const start = ta.selectionStart;
  const end = ta.selectionEnd;
  const sel = ta.value.substring(start, end);
  let before = '', after = '';
  switch (type) {
    case 'bold': before = '**'; after = '**'; break;
    case 'italic': before = '*'; after = '*'; break;
    case 'code': before = sel.includes('\n') ? '\n' + String.fromCharCode(96,96,96) + '\n' : String.fromCharCode(96); after = sel.includes('\n') ? '\n' + String.fromCharCode(96,96,96) + '\n' : String.fromCharCode(96); break;
    case 'heading': before = '## '; break;
    case 'link': before = '['; after = '](https://)'; break;
    case 'list': before = '- '; break;
  }
  const replacement = before + (sel || type) + after;
  ta.setRangeText(replacement, start, end, 'end');
  ta.focus();
  saveDraft();
}

document.querySelectorAll('.md-toolbar button[data-md]').forEach((btn) => {
  btn.addEventListener('click', (e) => {
    e.preventDefault();
    insertMd(btn.getAttribute('data-md'));
  });
});

// ── Fullscreen editor ──
const fsToggle = document.getElementById('fullscreen-toggle');
if (fsToggle) {
  fsToggle.addEventListener('click', () => {
    const overlay = document.createElement('div');
    overlay.className = 'editor-fullscreen';
    const fsTextarea = document.createElement('textarea');
    fsTextarea.value = contentInput.value;
    fsTextarea.placeholder = '# Start writing...';
    const actions = document.createElement('div');
    actions.className = 'fs-actions';
    const saveBtn = document.createElement('button');
    saveBtn.textContent = 'Save & Close';
    saveBtn.addEventListener('click', () => {
      contentInput.value = fsTextarea.value;
      saveDraft();
      overlay.remove();
    });
    const cancelBtn = document.createElement('button');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.style.background = 'transparent';
    cancelBtn.style.borderColor = 'var(--line)';
    cancelBtn.style.color = 'var(--muted)';
    cancelBtn.addEventListener('click', () => overlay.remove());
    actions.appendChild(saveBtn);
    actions.appendChild(cancelBtn);
    overlay.appendChild(fsTextarea);
    overlay.appendChild(actions);
    document.body.appendChild(overlay);
    fsTextarea.focus();
  });
}
// ── BearBlog import ──
const importBtn = document.getElementById('import-btn');
const importFile = document.getElementById('import-file');
const importStatus = document.getElementById('import-status');
if (importBtn && importFile) {
  importBtn.addEventListener('click', async () => {
    const file = importFile.files[0];
    if (!file) {
      importStatus.textContent = 'Please select a CSV file';
      return;
    }
    importStatus.textContent = 'Importing...';
    importBtn.disabled = true;
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch('/api/import', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) {
        importStatus.textContent = data.error || 'Import failed';
        importStatus.style.color = 'var(--accent)';
        return;
      }
      importStatus.textContent = 'Imported ' + data.imported + ', skipped ' + data.skipped + ', errors ' + data.errors;
      importStatus.style.color = '';
      await refreshPosts();
    } catch (e) {
      importStatus.textContent = e.message || 'Import failed';
    } finally {
      importBtn.disabled = false;
    }
  });
}
    </script>
  `
  );
}

function renderSimpleMessage(code, message) {
  return renderLayout(
    `${code} `,
    `
  < section class="panel" >
      <p class="eyebrow">${escapeHtml(code)}</p>
      <h1>${escapeHtml(message)}</h1>
      <p class="muted"><a href="/">Back</a></p>
    </section >
  `
  );
}

function renderLayout(title, body) {
  return `<!doctype html>
<html lang="zh-Hant">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500;600&display=swap" rel="stylesheet" />
    <title>${escapeHtml(title)}</title>
    <style>
:root {
  --bg-1: #f6f0e8;
  --bg-2: #eadfce;
  --ink: #2b261f;
  --ink-2: #3d362d;
  --muted: #666052;
  --panel: rgba(255,252,247,0.92);
  --line: rgba(57,47,38,0.15);
  --accent: #7b5034;
  --accent-glow: rgba(123,80,52,0.15);
  --code-bg: rgba(90,82,69,0.1);
  --font-mono: 'Fira Code','JetBrains Mono',Menlo,Consolas,monospace;
  --font-sans: 'Inter',-apple-system,BlinkMacSystemFont,sans-serif;
}
@media (prefers-color-scheme:dark) {
  :root {
    --bg-1: #0f1318;
    --bg-2: #141a22;
    --ink: #c8cfd8;
    --ink-2: #a0a8b4;
    --muted: #6b7580;
    --panel: rgba(20,26,34,0.92);
    --line: rgba(100,180,255,0.08);
    --accent: #5ca0d0;
    --accent-glow: rgba(92,160,208,0.12);
    --code-bg: rgba(255,255,255,0.06);
  }
}
*{box-sizing:border-box;margin:0;padding:0}
::selection{background:var(--accent-glow)}
body{color:var(--ink);font-family:var(--font-sans);background:linear-gradient(160deg,var(--bg-1),var(--bg-2));min-height:100vh;line-height:1.6;-webkit-font-smoothing:antialiased}
.reading-progress{position:fixed;top:0;left:0;height:3px;background:var(--accent);width:0%;z-index:9999;transition:width .1s linear}
main{width:min(980px,92vw);margin:2rem auto}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;box-shadow:0 12px 40px rgba(0,0,0,.06);padding:clamp(1.2rem,3vw,2rem);backdrop-filter:blur(8px)}
.wide{width:100%}
.eyebrow{font-family:var(--font-mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-size:.72rem;margin:0}
.eyebrow a{color:var(--muted);text-decoration:none}
.eyebrow a:hover{color:var(--accent)}
h1,h2,h3,h4{margin:.35rem 0 .7rem;line-height:1.25;color:var(--ink)}
h1{font-weight:700}
.muted{color:var(--muted)}
.stack{display:grid;gap:.6rem;margin-top:1rem}
label{font-family:var(--font-mono);font-size:.85rem;color:var(--muted)}
input,textarea,button,.link-button{font:inherit;border-radius:10px}
input,textarea{border:1px solid var(--line);background:rgba(255,255,255,.65);padding:.65rem .78rem;color:var(--ink);font-family:var(--font-mono);font-size:.92rem;transition:border-color .2s,box-shadow .2s}
@media(prefers-color-scheme:dark){input,textarea{background:rgba(255,255,255,.05)}}
input:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
textarea{min-height:360px;resize:vertical;line-height:1.65}
.small-textarea{min-height:110px}
button,.link-button{display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--accent);cursor:pointer;padding:.62rem .95rem;background:var(--accent);color:#f7eee2;text-decoration:none;font-weight:500;transition:all .2s;min-height:44px}
button:hover,.link-button:hover{filter:brightness(1.08);transform:translateY(-1px)}
button:active,.link-button:active{transform:translateY(0)}
.site-header{display:flex;align-items:start;justify-content:space-between;gap:1rem;margin-bottom:1rem}
.post-list{display:grid;gap:.9rem;margin:1rem 0 0;padding:0;list-style:none}
.post-item{border-bottom:1px dashed var(--line);padding-bottom:.7rem;transition:transform .15s}
.post-item:hover{transform:translateX(4px)}
.post-link{text-decoration:none;color:var(--ink);font-size:1.15rem;font-weight:600;transition:color .2s}
.post-link:hover{color:var(--accent)}
.site-nav{display:flex;flex-wrap:wrap;gap:.45rem;margin:.6rem 0 1rem}
.site-nav a{border:1px solid var(--line);border-radius:999px;padding:.35rem .65rem;text-decoration:none;color:var(--ink);font-size:.88rem;transition:all .2s}
.site-nav a:hover{border-color:var(--accent);color:var(--accent)}
.community-grid{display:grid;grid-template-columns:1fr 300px;gap:1.2rem}
.community-panel{border-left:1px solid var(--line);padding-left:1rem}
.mini-list{list-style:none;padding:0;margin:0 0 1rem;display:grid;gap:.35rem}
.mini-list li{line-height:1.5;font-size:.92rem}
.mini-list a{text-decoration:none;transition:color .2s}
.mini-list a:hover{color:var(--accent)}
.site-footer{margin-top:1.2rem;border-top:1px dashed var(--line);padding-top:.75rem;font-family:var(--font-mono);font-size:.82rem}
/* article */
.article-body{line-height:1.78;font-size:1.05rem}
.article-body h2,.article-body h3,.article-body h4{margin-top:1.6rem}
.article-body p{margin:.8rem 0}
.article-body blockquote{border-left:3px solid var(--accent);padding:.5rem 0 .5rem 1rem;margin:1rem 0;color:var(--muted);background:var(--accent-glow);border-radius:0 8px 8px 0}
.article-body ul,.article-body ol{padding-left:1.4rem;margin:.6rem 0}
.article-body img{max-width:100%;border-radius:8px;margin:.8rem 0}
.article-wrap{display:grid;grid-template-columns:minmax(0,1fr) 240px;gap:1.2rem}
.article-side{border-left:1px solid var(--line);padding-left:.9rem}
.article-body pre{background:rgba(30,28,24,.96);color:#e8e4dc;padding:1rem;border-radius:10px;overflow-x:auto;font-size:.88rem;line-height:1.5;margin:.8rem 0}
@media(prefers-color-scheme:dark){.article-body pre{background:rgba(255,255,255,.05);border:1px solid var(--line)}}
.article-body code{background:var(--code-bg);padding:.12rem .35rem;border-radius:4px;font-size:.88em;font-family:var(--font-mono)}
.article-body pre code{background:none;padding:0;font-size:inherit}
.read-time{font-family:var(--font-mono);font-size:.78rem;color:var(--muted);margin-left:.5rem}
/* back to top */
.back-top{position:fixed;bottom:1.5rem;right:1.5rem;width:42px;height:42px;border-radius:50%;background:var(--accent);color:#fff;border:none;font-size:1.1rem;cursor:pointer;opacity:0;transform:translateY(10px);transition:all .25s;z-index:100;display:flex;align-items:center;justify-content:center}
.back-top.visible{opacity:1;transform:translateY(0)}
/* admin */
.admin-shell{display:grid;gap:1rem}
.admin-grid{display:grid;grid-template-columns:280px minmax(0,1fr);gap:1.5rem}
.admin-list{border-right:1px solid var(--line);padding-right:1rem;display:grid;gap:.5rem;align-content:start}
.admin-list ul{list-style:none;margin:0;padding:0;display:grid;gap:.4rem}
.settings-toggle{display:none;width:100%;background:transparent;color:var(--muted);border:1px dashed var(--line);font-family:var(--font-mono);font-size:.82rem}
.settings-section{display:grid;gap:.5rem}
.post-item-btn{width:100%;text-align:left;background:rgba(255,255,255,.55);color:var(--ink);border:1px solid var(--line);font-size:.88rem;transition:all .15s}
@media(prefers-color-scheme:dark){.post-item-btn{background:rgba(255,255,255,.04)}}
.post-item-btn:hover{border-color:var(--accent)}
.post-item-btn.active{border-color:var(--accent);background:var(--accent-glow)}
.admin-editor{display:grid;gap:.5rem}
/* md toolbar */
.md-toolbar{display:flex;flex-wrap:wrap;gap:.3rem;padding:.4rem;background:var(--code-bg);border:1px solid var(--line);border-radius:8px}
.md-toolbar button{min-height:36px;min-width:36px;padding:.3rem .5rem;font-family:var(--font-mono);font-size:.78rem;background:transparent;color:var(--muted);border:1px solid transparent}
.md-toolbar button:hover{background:var(--accent-glow);border-color:var(--line);color:var(--ink);transform:none}
.fullscreen-btn{background:transparent!important;color:var(--muted)!important;border:1px solid var(--line)!important;font-family:var(--font-mono)!important;font-size:.78rem!important;min-height:36px}
.row-actions{display:flex;flex-wrap:wrap;gap:.5rem}
.inline-check{display:inline-flex;align-items:center;gap:.5rem;margin:.4rem 0}
.inline-check input[type="checkbox"]{width:18px;height:18px;accent-color:var(--accent)}
a{color:var(--accent)}
code{font-family:var(--font-mono)}
/* fullscreen overlay */
.editor-fullscreen{position:fixed;inset:0;z-index:9000;background:var(--bg-1);display:flex;flex-direction:column;padding:.8rem;padding-top:env(safe-area-inset-top,.8rem);padding-bottom:env(safe-area-inset-bottom,.8rem)}
.editor-fullscreen textarea{flex:1;border-radius:8px;font-size:16px;resize:none}
.editor-fullscreen .fs-actions{display:flex;gap:.5rem;padding-top:.5rem}
.editor-fullscreen .fs-actions button{flex:1}
/* responsive */
@media(max-width:860px){
  main{margin-top:1rem;width:95vw}
  .admin-grid{grid-template-columns:1fr}
  .admin-list{border-right:0;border-bottom:1px solid var(--line);padding-right:0;padding-bottom:.9rem}
  .settings-toggle{display:flex}
  .settings-section.collapsed{display:none}
  .site-header{flex-direction:column;align-items:stretch}
  .community-grid{grid-template-columns:1fr}
  .community-panel{border-left:0;border-top:1px solid var(--line);padding-left:0;padding-top:.9rem}
  .article-wrap{grid-template-columns:1fr}
  .article-side{border-left:0;border-top:1px solid var(--line);padding-left:0;padding-top:.8rem}
  input,textarea,button,.link-button{font-size:16px;min-height:44px}
  textarea{min-height:60vh}
  .admin-editor .row-actions{position:sticky;bottom:0;background:var(--panel);padding:.5rem;border:1px solid var(--line);border-radius:10px;z-index:10}
  .back-top{bottom:4.5rem}
}
@media(max-width:480px){
  .panel{padding:.9rem;border-radius:12px}
  h1{font-size:1.3rem}
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

function toScriptJson(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
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
  return `# Welcome to ${displayName} \n\n你已成功建立站點：\`${slug}.${baseDomain}\`。\n\n- 前台首頁：https://${slug}.${baseDomain}\n- 後台編輯：https://${slug}.${baseDomain}/admin\n\n現在你可以直接在後台開始寫作，體驗會偏向 Bear 的簡潔流。\n`;
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
