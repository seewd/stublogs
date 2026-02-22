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
const LEGACY_FOOTER_NOTE = "在這裡，把語文寫成你自己。";
const POSTS_PAGE_SIZE = 10;
const COMMENTS_PAGE_SIZE = 20;

const LOGIN_RATE_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_RATE_MAX_ATTEMPTS = 5;
const loginAttempts = new Map();
const COMMENT_RATE_WINDOW_MS = 60 * 1000;
const COMMENT_RATE_MAX_ATTEMPTS = 6;
const commentAttempts = new Map();
let commentsTableReadyPromise = null;
let postsColumnsReadyPromise = null;

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
    const siteConfig = await getSiteConfig(env, site);
    const page = parsePositiveInt(url.searchParams.get("page"), 1, 1, 9999);
    const postsPage = await listPostsPage(env, site.id, page, POSTS_PAGE_SIZE);
    const communitySites = await listCommunitySites(env, site.slug, 12);
    const campusFeed = await listCampusFeed(env, site.id, 18);
    return html(
      renderSiteHomePage(
        site,
        siteConfig,
        postsPage.posts,
        communitySites,
        campusFeed,
        baseDomain,
        postsPage
      ),
      200
    );
  }

  if (path.startsWith("/preview/")) {
    const previewSlug = path.slice("/preview/".length).toLowerCase();
    if (!previewSlug || previewSlug.includes("/")) {
      return notFound("Preview not found");
    }

    const authed = await isSiteAuthenticated(request, env, site.slug);
    if (!authed) {
      return html(renderSimpleMessage("401", "Preview requires login"), 401);
    }

    const post = await getPostMeta(env, site.id, previewSlug, true);
    if (!post) {
      return notFound("Preview not found");
    }

    const file = await githubReadFile(env, getPostFilePath(site.slug, post.postSlug));
    if (!file) {
      return notFound("Post content missing");
    }

    const siteConfig = await getSiteConfig(env, site);
    const communitySites = !siteConfig.hideCommunitySites
      ? await listCommunitySites(env, site.slug, 8)
      : [];
    const commentPage = parsePositiveInt(url.searchParams.get("cpage"), 1, 1, 9999);
    const commentsData = siteConfig.commentsEnabled
      ? await listPostComments(env, site.id, post.postSlug, commentPage, COMMENTS_PAGE_SIZE)
      : { comments: [], page: 1, totalPages: 1, total: 0 };
    const articleHtml = renderMarkdown(file.content);
    return html(
      renderPostPage(site, siteConfig, post, articleHtml, communitySites, baseDomain, {
        previewMode: true,
        comments: commentsData.comments,
        commentsPage: commentsData.page,
        commentsTotalPages: commentsData.totalPages,
        commentsEnabled: siteConfig.commentsEnabled,
        commentsTotal: commentsData.total,
        commentBasePath: `/preview/${encodeURIComponent(post.postSlug)}`,
      }),
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
  const communitySites = !siteConfig.hideCommunitySites
    ? await listCommunitySites(env, site.slug, 8)
    : [];
  const commentPage = parsePositiveInt(url.searchParams.get("cpage"), 1, 1, 9999);
  const commentsData = siteConfig.commentsEnabled
    ? await listPostComments(env, site.id, post.postSlug, commentPage, COMMENTS_PAGE_SIZE)
    : { comments: [], page: 1, totalPages: 1, total: 0 };
  const articleHtml = renderMarkdown(file.content);
  return html(
    renderPostPage(site, siteConfig, post, articleHtml, communitySites, baseDomain, {
      comments: commentsData.comments,
      commentsPage: commentsData.page,
      commentsTotalPages: commentsData.totalPages,
      commentsEnabled: siteConfig.commentsEnabled,
      commentsTotal: commentsData.total,
      commentBasePath: `/${encodeURIComponent(post.postSlug)}`,
    }),
    200
  );
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
            colorTheme: "default",
            footerNote: "",
            customCss: "",
            headerLinks: [],
            hideCommunitySites: false,
            hideCampusFeed: false,
            commentsEnabled: true,
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
        now,
        { excludeFromCampusFeed: true }
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
    const currentConfig = await getSiteConfig(env, site);
    const now = new Date().toISOString();

    const displayName = sanitizeName(
      body.displayName ?? currentConfig.displayName ?? site.displayName
    ) || site.slug;
    const description = sanitizeDescription(
      body.description ?? currentConfig.description ?? ""
    );
    const heroTitle = sanitizeTitle(
      body.heroTitle ?? currentConfig.heroTitle ?? ""
    );
    const heroSubtitle = sanitizeDescription(
      body.heroSubtitle ?? currentConfig.heroSubtitle ?? ""
    );
    const colorTheme = sanitizeColorTheme(
      body.colorTheme ?? currentConfig.colorTheme ?? "default"
    );
    const footerNote = sanitizeDescription(
      body.footerNote ?? currentConfig.footerNote ?? ""
    );
    const customCss = sanitizeCustomCss(
      body.customCss ?? currentConfig.customCss ?? ""
    );
    const headerLinks = Array.isArray(body.headerLinks)
      ? sanitizeHeaderLinks(body.headerLinks)
      : sanitizeHeaderLinks(currentConfig.headerLinks || []);
    const hideCommunitySites = body.hideCommunitySites === undefined
      ? Boolean(currentConfig.hideCommunitySites)
      : Boolean(body.hideCommunitySites);
    const hideCampusFeed = body.hideCampusFeed === undefined
      ? Boolean(currentConfig.hideCampusFeed)
      : Boolean(body.hideCampusFeed);
    const commentsEnabled = body.commentsEnabled === undefined
      ? Boolean(currentConfig.commentsEnabled)
      : Boolean(body.commentsEnabled);

    const nextConfig = normalizeSiteConfig(
      {
        slug: site.slug,
        displayName,
        description,
        heroTitle,
        heroSubtitle,
        colorTheme,
        footerNote,
        customCss,
        headerLinks,
        hideCommunitySites,
        hideCampusFeed,
        commentsEnabled,
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

  if (request.method === "GET" && path === "/api/admin/comments") {
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

    await ensureCommentsTable(env);
    const postSlug = String(url.searchParams.get("postSlug") || "").trim().toLowerCase();
    const page = parsePositiveInt(url.searchParams.get("page"), 1, 1, 9999);
    const pageSize = COMMENTS_PAGE_SIZE;

    if (postSlug) {
      const commentsData = await listPostComments(env, site.id, postSlug, page, pageSize);
      return json(
        {
          postSlug,
          comments: commentsData.comments,
          page: commentsData.page,
          totalPages: commentsData.totalPages,
          total: commentsData.total,
        },
        200
      );
    }

    const commentsData = await listSiteComments(env, site.id, page, pageSize);
    return json(
      {
        comments: commentsData.comments,
        page: commentsData.page,
        totalPages: commentsData.totalPages,
        total: commentsData.total,
      },
      200
    );
  }

  if (request.method === "GET" && path === "/api/comments") {
    if (!hostSlug) {
      return json({ error: "Missing site context" }, 400);
    }
    const site = await getSiteBySlug(env, hostSlug);
    if (!site) {
      return json({ error: "Site not found" }, 404);
    }
    const postSlug = String(url.searchParams.get("postSlug") || "").trim().toLowerCase();
    if (!postSlug) {
      return json({ error: "Missing post slug" }, 400);
    }

    const post = await getPostMeta(env, site.id, postSlug, false);
    if (!post) {
      return json({ error: "Post not found" }, 404);
    }

    const siteConfig = await getSiteConfig(env, site);
    if (!siteConfig.commentsEnabled) {
      return json({ comments: [], page: 1, totalPages: 1, total: 0 }, 200);
    }

    const page = parsePositiveInt(url.searchParams.get("page"), 1, 1, 9999);
    const commentsData = await listPostComments(env, site.id, postSlug, page, COMMENTS_PAGE_SIZE);
    return json(
      {
        comments: commentsData.comments,
        page: commentsData.page,
        totalPages: commentsData.totalPages,
        total: commentsData.total,
      },
      200
    );
  }

  if (request.method === "POST" && path === "/api/comments") {
    if (!hostSlug) {
      return json({ error: "Missing site context" }, 400);
    }
    const site = await getSiteBySlug(env, hostSlug);
    if (!site) {
      return json({ error: "Site not found" }, 404);
    }

    const siteConfig = await getSiteConfig(env, site);
    if (!siteConfig.commentsEnabled) {
      return json({ error: "Comments are disabled for this site" }, 403);
    }

    const clientIp = request.headers.get("cf-connecting-ip") || "unknown";
    const rateKey = `${clientIp}:${site.slug}:comments`;
    const nowTs = Date.now();
    const attempts = commentAttempts.get(rateKey) || [];
    const recent = attempts.filter((t) => nowTs - t < COMMENT_RATE_WINDOW_MS);
    if (recent.length >= COMMENT_RATE_MAX_ATTEMPTS) {
      return json({ error: "Too many comments, please try later" }, 429);
    }

    const body = await readJson(request);
    const postSlug = String(body.postSlug || "").trim().toLowerCase();
    const authorName = sanitizeCommentAuthor(body.authorName || "");
    const authorSite = sanitizeOptionalSiteSlug(body.authorSiteSlug || "");
    const content = sanitizeCommentContent(body.content || "");
    if (!postSlug) {
      return json({ error: "Missing post slug" }, 400);
    }
    if (!authorName) {
      return json({ error: "Name is required" }, 400);
    }
    if (!content) {
      return json({ error: "Comment content is required" }, 400);
    }

    const post = await getPostMeta(env, site.id, postSlug, false);
    if (!post) {
      return json({ error: "Post not found" }, 404);
    }

    recent.push(nowTs);
    commentAttempts.set(rateKey, recent);
    const created = await createComment(env, site.id, postSlug, authorName, authorSite, content);
    return json({ ok: true, comment: created }, 201);
  }

  if (request.method === "DELETE" && path.startsWith("/api/comments/")) {
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

    const rawId = path.slice("/api/comments/".length);
    const id = Number(rawId);
    if (!Number.isInteger(id) || id <= 0) {
      return json({ error: "Invalid comment id" }, 400);
    }
    const deleted = await deleteComment(env, site.id, id);
    if (!deleted) {
      return json({ error: "Comment not found" }, 404);
    }
    return json({ ok: true }, 200);
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

  if (request.method === "DELETE" && path.startsWith("/api/posts/")) {
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

    try {
      await githubDeleteFile(
        env,
        getPostFilePath(site.slug, post.postSlug),
        `feat(${site.slug}): delete post ${post.postSlug}`
      );
      await deletePostMeta(env, site.id, post.postSlug);
      await deleteCommentsByPost(env, site.id, post.postSlug);
    } catch (error) {
      console.error("Failed to delete post", error);
      return json(
        {
          error: "Failed to delete post",
          detail: String(error && error.message ? error.message : error),
        },
        502
      );
    }

    return json({ ok: true, postSlug: post.postSlug }, 200);
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
    const previousSlugRaw = String(body.previousSlug || "").trim().toLowerCase();
    const previousSlug = previousSlugRaw && !previousSlugRaw.includes("/")
      ? previousSlugRaw
      : "";
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
    const isRenaming = Boolean(previousSlug && previousSlug !== postSlug);

    try {
      let existingPost = null;
      let previousPost = null;

      if (isRenaming) {
        previousPost = await getPostMeta(env, site.id, previousSlug, true);
        if (!previousPost) {
          return json({ error: "Original post not found" }, 404);
        }
      }

      existingPost = await getPostMeta(env, site.id, postSlug, true);
      if (existingPost && isRenaming) {
        return json({ error: "Target post slug already exists" }, 409);
      }

      await githubWriteFile(
        env,
        getPostFilePath(site.slug, postSlug),
        content,
        `feat(${site.slug}): update post ${postSlug}`
      );

      if (isRenaming) {
        await githubDeleteFile(
          env,
          getPostFilePath(site.slug, previousSlug),
          `feat(${site.slug}): rename post ${previousSlug} -> ${postSlug}`
        );
        await deletePostMeta(env, site.id, previousSlug);
        await moveCommentsToPost(env, site.id, previousSlug, postSlug);
      }

      const createdAt = previousPost?.createdAt || existingPost?.createdAt || now;
      await upsertPostMeta(
        env,
        site.id,
        postSlug,
        title,
        description,
        published,
        now,
        createdAt
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
  const hasExcludeColumn = await hasPostsColumn(env, "exclude_from_campus_feed");
  const visibilityClause = hasExcludeColumn
    ? "p.published = 1 AND p.exclude_from_campus_feed = 0"
    : "p.published = 1 AND NOT (p.post_slug = 'hello-world' AND p.title = 'Hello World')";
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
      WHERE ${visibilityClause} AND p.site_id != ?
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
      WHERE ${visibilityClause}
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

async function listPostsPage(env, siteId, page = 1, pageSize = POSTS_PAGE_SIZE) {
  const safePageSize = Math.min(Math.max(Number(pageSize) || POSTS_PAGE_SIZE, 1), 60);
  const safePage = Math.max(Number(page) || 1, 1);
  const offset = (safePage - 1) * safePageSize;

  const [rowsResult, totalResult] = await Promise.all([
    env.DB.prepare(
      `SELECT
        post_slug AS postSlug,
        title,
        description,
        published,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM posts
      WHERE site_id = ? AND published = 1
      ORDER BY updated_at DESC
      LIMIT ? OFFSET ?`
    )
      .bind(siteId, safePageSize, offset)
      .all(),
    env.DB.prepare(
      `SELECT COUNT(*) AS total
      FROM posts
      WHERE site_id = ? AND published = 1`
    )
      .bind(siteId)
      .first(),
  ]);

  const total = Number(totalResult?.total || 0);
  const totalPages = Math.max(1, Math.ceil(total / safePageSize));
  const boundedPage = Math.min(safePage, totalPages);

  if (boundedPage !== safePage) {
    return listPostsPage(env, siteId, boundedPage, safePageSize);
  }

  return {
    posts: rowsResult.results || [],
    total,
    page: boundedPage,
    pageSize: safePageSize,
    totalPages,
    hasPrev: boundedPage > 1,
    hasNext: boundedPage < totalPages,
  };
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

async function ensureCommentsTable(env) {
  if (!commentsTableReadyPromise) {
    commentsTableReadyPromise = (async () => {
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS comments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          site_id INTEGER NOT NULL,
          post_slug TEXT NOT NULL,
          author_name TEXT NOT NULL,
          author_site_slug TEXT NOT NULL DEFAULT '',
          content TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
          FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
        )`
      ).run();
      await env.DB.prepare(
        `CREATE INDEX IF NOT EXISTS idx_comments_site_post_created
         ON comments(site_id, post_slug, created_at DESC)`
      ).run();
      await env.DB.prepare(
        `CREATE INDEX IF NOT EXISTS idx_comments_site_created
         ON comments(site_id, created_at DESC)`
      ).run();
    })().catch((error) => {
      commentsTableReadyPromise = null;
      throw error;
    });
  }
  return commentsTableReadyPromise;
}

async function getPostsColumns(env) {
  if (!postsColumnsReadyPromise) {
    postsColumnsReadyPromise = (async () => {
      const result = await env.DB.prepare("PRAGMA table_info(posts)").all();
      const rows = result.results || [];
      return new Set(
        rows
          .map((item) => String(item.name || "").toLowerCase())
          .filter(Boolean)
      );
    })().catch((error) => {
      postsColumnsReadyPromise = null;
      throw error;
    });
  }
  return postsColumnsReadyPromise;
}

async function hasPostsColumn(env, columnName) {
  try {
    const columns = await getPostsColumns(env);
    return columns.has(String(columnName || "").toLowerCase());
  } catch (error) {
    console.error("Failed to inspect posts columns", error);
    return false;
  }
}

async function listPostComments(env, siteId, postSlug, page = 1, pageSize = COMMENTS_PAGE_SIZE) {
  await ensureCommentsTable(env);
  const safePageSize = Math.min(Math.max(Number(pageSize) || COMMENTS_PAGE_SIZE, 1), 80);
  const safePage = Math.max(Number(page) || 1, 1);
  const offset = (safePage - 1) * safePageSize;

  const [rowsResult, totalResult] = await Promise.all([
    env.DB.prepare(
      `SELECT
        id,
        post_slug AS postSlug,
        author_name AS authorName,
        author_site_slug AS authorSiteSlug,
        content,
        created_at AS createdAt
      FROM comments
      WHERE site_id = ? AND post_slug = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?`
    )
      .bind(siteId, postSlug, safePageSize, offset)
      .all(),
    env.DB.prepare(
      `SELECT COUNT(*) AS total
       FROM comments
       WHERE site_id = ? AND post_slug = ?`
    )
      .bind(siteId, postSlug)
      .first(),
  ]);

  const total = Number(totalResult?.total || 0);
  const totalPages = Math.max(1, Math.ceil(total / safePageSize));
  const boundedPage = Math.min(safePage, totalPages);
  if (boundedPage !== safePage) {
    return listPostComments(env, siteId, postSlug, boundedPage, safePageSize);
  }

  const comments = (rowsResult.results || []).map((item) => ({
    id: Number(item.id),
    postSlug: item.postSlug,
    authorName: item.authorName,
    authorSiteSlug: item.authorSiteSlug || "",
    content: item.content,
    createdAt: item.createdAt,
  }));

  return {
    comments,
    total,
    page: boundedPage,
    totalPages,
    pageSize: safePageSize,
  };
}

async function listSiteComments(env, siteId, page = 1, pageSize = COMMENTS_PAGE_SIZE) {
  await ensureCommentsTable(env);
  const safePageSize = Math.min(Math.max(Number(pageSize) || COMMENTS_PAGE_SIZE, 1), 80);
  const safePage = Math.max(Number(page) || 1, 1);
  const offset = (safePage - 1) * safePageSize;

  const [rowsResult, totalResult] = await Promise.all([
    env.DB.prepare(
      `SELECT
        id,
        post_slug AS postSlug,
        author_name AS authorName,
        author_site_slug AS authorSiteSlug,
        content,
        created_at AS createdAt
      FROM comments
      WHERE site_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?`
    )
      .bind(siteId, safePageSize, offset)
      .all(),
    env.DB.prepare("SELECT COUNT(*) AS total FROM comments WHERE site_id = ?")
      .bind(siteId)
      .first(),
  ]);

  const total = Number(totalResult?.total || 0);
  const totalPages = Math.max(1, Math.ceil(total / safePageSize));
  const boundedPage = Math.min(safePage, totalPages);
  if (boundedPage !== safePage) {
    return listSiteComments(env, siteId, boundedPage, safePageSize);
  }

  const comments = (rowsResult.results || []).map((item) => ({
    id: Number(item.id),
    postSlug: item.postSlug,
    authorName: item.authorName,
    authorSiteSlug: item.authorSiteSlug || "",
    content: item.content,
    createdAt: item.createdAt,
  }));

  return {
    comments,
    total,
    page: boundedPage,
    totalPages,
    pageSize: safePageSize,
  };
}

async function createComment(env, siteId, postSlug, authorName, authorSiteSlug, content) {
  await ensureCommentsTable(env);
  const createdAt = new Date().toISOString();
  const result = await env.DB.prepare(
    `INSERT INTO comments (site_id, post_slug, author_name, author_site_slug, content, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(siteId, postSlug, authorName, authorSiteSlug, content, createdAt)
    .run();

  const id = Number(result.meta?.last_row_id || 0);
  return {
    id,
    postSlug,
    authorName,
    authorSiteSlug,
    content,
    createdAt,
  };
}

async function deleteComment(env, siteId, commentId) {
  await ensureCommentsTable(env);
  const result = await env.DB.prepare(
    "DELETE FROM comments WHERE id = ? AND site_id = ?"
  )
    .bind(commentId, siteId)
    .run();
  return Number(result.meta?.changes || 0) > 0;
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
  createdAt,
  options = {}
) {
  const created = createdAt || updatedAt;
  const excludeFromCampusFeed = options.excludeFromCampusFeed ? 1 : 0;
  const hasExcludeColumn = await hasPostsColumn(env, "exclude_from_campus_feed");

  if (hasExcludeColumn) {
    return env.DB.prepare(
      `INSERT INTO posts (
        site_id,
        post_slug,
        title,
        description,
        published,
        exclude_from_campus_feed,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(site_id, post_slug)
      DO UPDATE SET
        title = excluded.title,
        description = excluded.description,
        published = excluded.published,
        exclude_from_campus_feed = excluded.exclude_from_campus_feed,
        updated_at = excluded.updated_at`
    )
      .bind(
        siteId,
        postSlug,
        title,
        description,
        published,
        excludeFromCampusFeed,
        created,
        updatedAt
      )
      .run();
  }

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

async function deletePostMeta(env, siteId, postSlug) {
  const result = await env.DB.prepare(
    "DELETE FROM posts WHERE site_id = ? AND post_slug = ?"
  )
    .bind(siteId, postSlug)
    .run();
  return Number(result.meta?.changes || 0) > 0;
}

async function deleteCommentsByPost(env, siteId, postSlug) {
  await ensureCommentsTable(env);
  await env.DB.prepare(
    "DELETE FROM comments WHERE site_id = ? AND post_slug = ?"
  )
    .bind(siteId, postSlug)
    .run();
}

async function moveCommentsToPost(env, siteId, fromPostSlug, toPostSlug) {
  await ensureCommentsTable(env);
  await env.DB.prepare(
    `UPDATE comments
     SET post_slug = ?
     WHERE site_id = ? AND post_slug = ?`
  )
    .bind(toPostSlug, siteId, fromPostSlug)
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

async function githubDeleteFile(env, filePath, message) {
  const config = getGithubConfig(env);
  const existing = await githubReadFile(env, filePath);
  if (!existing || !existing.sha) {
    return { deleted: false };
  }
  const encodedPath = encodeGitHubPath(filePath);
  const response = await githubRequest(env, `/contents/${encodedPath}`, {
    method: "DELETE",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message,
      branch: config.branch,
      sha: existing.sha,
    }),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`GitHub delete failed: ${response.status} ${detail}`);
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
      colorTheme: "default",
      footerNote: "",
      customCss: "",
      headerLinks: [],
      hideCommunitySites: false,
      hideCampusFeed: false,
      commentsEnabled: true,
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

function sanitizeColorTheme(value) {
  const theme = String(value || "")
    .trim()
    .toLowerCase();
  if (
    theme === "ocean" ||
    theme === "forest" ||
    theme === "violet" ||
    theme === "sunset" ||
    theme === "mint" ||
    theme === "graphite"
  ) {
    return theme;
  }
  return "default";
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
      colorTheme: "default",
      footerNote: "",
      customCss: "",
      headerLinks: [],
      hideCommunitySites: false,
      hideCampusFeed: false,
      commentsEnabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      exportVersion: SITE_CONFIG_VERSION,
    };

  const merged = {
    ...base,
    ...(rawConfig && typeof rawConfig === "object" ? rawConfig : {}),
  };
  const normalizedFooterNote = sanitizeDescription(merged.footerNote || base.footerNote);

  return {
    slug: String(merged.slug || base.slug).toLowerCase(),
    displayName: sanitizeName(merged.displayName || base.displayName) || base.slug,
    description: sanitizeDescription(merged.description || ""),
    heroTitle: sanitizeTitle(merged.heroTitle || ""),
    heroSubtitle: sanitizeDescription(merged.heroSubtitle || ""),
    colorTheme: sanitizeColorTheme(merged.colorTheme || base.colorTheme || "default"),
    footerNote: normalizedFooterNote === LEGACY_FOOTER_NOTE ? "" : normalizedFooterNote,
    customCss: sanitizeCustomCss(merged.customCss || base.customCss || ""),
    headerLinks: sanitizeHeaderLinks(Array.isArray(merged.headerLinks) ? merged.headerLinks : []),
    hideCommunitySites: Boolean(merged.hideCommunitySites),
    hideCampusFeed: Boolean(merged.hideCampusFeed),
    commentsEnabled: merged.commentsEnabled === undefined ? true : Boolean(merged.commentsEnabled),
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
    colorTheme: "default",
    footerNote: "",
    customCss: "",
    headerLinks: [],
    hideCommunitySites: false,
    hideCampusFeed: false,
    commentsEnabled: true,
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
  headers.set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
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
      "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
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

function parsePositiveInt(value, fallback = 1, min = 1, max = 9999) {
  const parsed = Number.parseInt(String(value || ""), 10);
  if (!Number.isFinite(parsed) || parsed < min) {
    return fallback;
  }
  if (parsed > max) {
    return max;
  }
  return parsed;
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

function sanitizeCustomCss(value) {
  return String(value || "")
    .replace(/\u0000/g, "")
    .replace(/<\/style/gi, "")
    .trim()
    .slice(0, 8000);
}

function sanitizeCommentAuthor(value) {
  return sanitizeName(value)
    .replace(/\s+/g, " ")
    .slice(0, 40);
}

function sanitizeCommentContent(value) {
  return String(value || "")
    .replace(/\r\n/g, "\n")
    .trim()
    .slice(0, 2000);
}

function sanitizeOptionalSiteSlug(value) {
  const slug = String(value || "").trim().toLowerCase();
  if (!slug) {
    return "";
  }
  if (slug.length < 2 || slug.length > 30) {
    return "";
  }
  if (!/^[a-z0-9-]+$/.test(slug)) {
    return "";
  }
  if (slug.startsWith("-") || slug.endsWith("-") || slug.includes("--")) {
    return "";
  }
  return slug;
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
      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src https://fonts.gstatic.com https://cdn.jsdelivr.net data:; connect-src 'self'; img-src 'self' data: https:; frame-ancestors 'none'",
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
  `, 'default'
  );
}

function renderSiteHomePage(
  site,
  siteConfig,
  posts,
  communitySites,
  campusFeed,
  baseDomain,
  postsPage = null
) {
  const heading = siteConfig.heroTitle || site.displayName;
  const subtitle = siteConfig.heroSubtitle || site.description || "";

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
    : `<li class="post-item muted">還沒有已發佈文章。</li>`;

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

  const pagination = postsPage && postsPage.totalPages > 1
    ? `<nav class="pager" aria-label="文章分頁">
        <a class="${postsPage.hasPrev ? "" : "disabled"}" href="${postsPage.hasPrev ? (postsPage.page - 1 <= 1 ? "/" : `/?page=${postsPage.page - 1}`) : "#"}">上一頁</a>
        <span class="muted">第 ${postsPage.page} / ${postsPage.totalPages} 頁</span>
        <a class="${postsPage.hasNext ? "" : "disabled"}" href="${postsPage.hasNext ? `/?page=${postsPage.page + 1}` : "#"}">下一頁</a>
      </nav>`
    : "";

  return renderLayout(
    site.displayName,
    `
    <section class="panel wide site-home-shell">
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
      ${renderThemeControlDock("front")}
      ${navLinks}

      <div class="community-grid">
        <section>
          <h2>文章</h2>
          <ul class="post-list">
            ${list}
          </ul>
          ${pagination}
        </section>
        ${(!siteConfig.hideCommunitySites || !siteConfig.hideCampusFeed) ? `
        <aside class="community-panel">
          ${!siteConfig.hideCommunitySites ? `<h3>同學新站</h3><ul class="mini-list">${peerSites}</ul>` : ''}
          ${!siteConfig.hideCampusFeed ? `<h3>全校最新文章</h3><ul class="mini-list">${feedItems}</ul>` : ''}
        </aside>
        ` : ''}
      </div>

      ${(siteConfig.footerNote)
      ? `<footer class="site-footer muted">${escapeHtml(siteConfig.footerNote)}</footer>`
      : ''}
    </section>
  `, siteConfig.colorTheme || 'default', siteConfig.customCss || ""
  );
}

function renderPostPage(site, siteConfig, post, articleHtml, communitySites, baseDomain, options = {}) {
  const previewMode = Boolean(options.previewMode);
  const commentsEnabled = options.commentsEnabled !== false;
  const comments = Array.isArray(options.comments) ? options.comments : [];
  const commentsPage = Math.max(Number(options.commentsPage) || 1, 1);
  const commentsTotalPages = Math.max(Number(options.commentsTotalPages) || 1, 1);
  const commentBasePath = String(
    options.commentBasePath || `/${encodeURIComponent(post.postSlug)}`
  );
  const commentsTotal = Number(options.commentsTotal || comments.length || 0);
  const showCommunityPanel = !siteConfig.hideCommunitySites;

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

  const commentsList = comments.length
    ? comments
      .map((item) => {
        const author = item.authorSiteSlug
          ? `<a href="https://${escapeHtml(item.authorSiteSlug)}.${escapeHtml(baseDomain)}" target="_blank" rel="noreferrer noopener">${escapeHtml(item.authorName)}</a>`
          : escapeHtml(item.authorName);
        return `<li class="comment-item">
          <p class="comment-meta">${author} · ${escapeHtml(formatDate(item.createdAt))}</p>
          <p class="comment-content">${escapeHtml(item.content).replace(/\n/g, "<br />")}</p>
        </li>`;
      })
      .join("")
    : `<li class="comment-item muted">目前還沒有留言。</li>`;

  const commentPager = commentsTotalPages > 1
    ? `<nav class="pager comments-pager" aria-label="留言分頁">
        <a class="${commentsPage > 1 ? "" : "disabled"}" href="${commentsPage > 1 ? `${commentBasePath}?cpage=${commentsPage - 1}#comments` : "#"}">上一頁</a>
        <span class="muted">留言 ${commentsPage} / ${commentsTotalPages}</span>
        <a class="${commentsPage < commentsTotalPages ? "" : "disabled"}" href="${commentsPage < commentsTotalPages ? `${commentBasePath}?cpage=${commentsPage + 1}#comments` : "#"}">下一頁</a>
      </nav>`
    : "";

  // Estimate read time (~400 chars/min for Chinese)
  const charCount = articleHtml.replace(/<[^>]+>/g, "").length;
  const readMinutes = Math.max(1, Math.round(charCount / 400));

  return renderLayout(
    `${post.title} - ${site.displayName}`,
    `
    <div class="reading-progress" id="reading-progress"></div>
    <section class="panel wide article-wrap">
      <article class="article">
        <p class="eyebrow"><a href="/">← ${escapeHtml(site.displayName)}</a> · ${escapeHtml(
      site.slug
    )}.${escapeHtml(baseDomain)} ${previewMode ? '<span class="preview-badge">Preview</span>' : ''}</p>
        <h1>${escapeHtml(post.title)}</h1>
        <p class="muted">${escapeHtml(formatDate(post.updatedAt))} <span class="read-time">· ${readMinutes} min read</span></p>
        ${renderThemeControlDock("front")}
        <div class="article-body">${articleHtml}</div>
      </article>
      ${showCommunityPanel ? `
      <aside class="article-side">
        <h3>同學站點</h3>
        <ul class="mini-list">${peerSites}</ul>
      </aside>
      ` : ''}
    </section>
    ${commentsEnabled ? `
    <section id="comments" class="panel wide comment-panel">
      <h2>留言 (${commentsTotal})</h2>
      <ul class="comment-list">${commentsList}</ul>
      ${commentPager}
      <form id="comment-form" class="stack" autocomplete="off">
        <label>名稱</label>
        <input id="comment-author" maxlength="40" required placeholder="你的名字" />
        <label>你的站點 slug（可選）</label>
        <input id="comment-site" maxlength="30" placeholder="alice" />
        <label>留言內容</label>
        <textarea id="comment-content" class="small-textarea" maxlength="2000" required placeholder="寫下你的留言"></textarea>
        <button id="comment-submit" type="submit">送出留言</button>
      </form>
      <p id="comment-status" class="muted"></p>
    </section>
    ` : ""}
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

        const form = document.getElementById('comment-form');
        const statusEl = document.getElementById('comment-status');
        if (form && statusEl) {
          const authorInput = document.getElementById('comment-author');
          const siteInput = document.getElementById('comment-site');
          const contentInput = document.getElementById('comment-content');
          const submitBtn = document.getElementById('comment-submit');
          const commentsSection = document.getElementById('comments');
          const commentsListEl = commentsSection ? commentsSection.querySelector('.comment-list') : null;
          const commentsTitleEl = commentsSection ? commentsSection.querySelector('h2') : null;
          const storageKey = 'stublogs-comment-profile:' + location.host;
          let isSubmittingComment = false;

          try {
            const profile = JSON.parse(localStorage.getItem(storageKey) || '{}');
            if (profile.authorName) authorInput.value = profile.authorName;
            if (profile.authorSiteSlug) siteInput.value = profile.authorSiteSlug;
          } catch {}

          function escapeHtml(value) {
            return String(value || '')
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
          }

          function addCommentToList(comment) {
            if (!commentsListEl || !comment) return;

            const placeholder = commentsListEl.querySelector('.comment-item.muted');
            if (placeholder) {
              placeholder.remove();
            }

            const author = comment.authorSiteSlug
              ? comment.authorName + ' · ' + comment.authorSiteSlug + '.bdfz.net'
              : comment.authorName;
            const createdAt = comment.createdAt
              ? new Date(comment.createdAt).toLocaleString('zh-Hant')
              : new Date().toLocaleString('zh-Hant');
            const safeContent = escapeHtml(comment.content || '').replace(/\n/g, '<br />');

            const item = document.createElement('li');
            item.className = 'comment-item';
            item.innerHTML =
              '<p class="comment-meta">' + escapeHtml(author) + ' · ' + escapeHtml(createdAt) + '</p>' +
              '<p class="comment-content">' + safeContent + '</p>';

            commentsListEl.prepend(item);
          }

          function bumpCommentCount() {
            if (!commentsTitleEl) return;
            const text = commentsTitleEl.textContent || '';
            const match = text.match(/\((\d+)\)/);
            const current = match ? Number(match[1]) : 0;
            commentsTitleEl.textContent = '留言 (' + (current + 1) + ')';
          }

          function setCommentStatus(message, isError) {
            statusEl.textContent = message;
            statusEl.style.color = isError ? '#ae3a22' : 'var(--muted)';
          }

          form.addEventListener('submit', async (event) => {
            event.preventDefault();
            if (isSubmittingComment) {
              return;
            }
            const payload = {
              postSlug: ${JSON.stringify(post.postSlug)},
              authorName: authorInput.value.trim(),
              authorSiteSlug: siteInput.value.trim().toLowerCase(),
              content: contentInput.value.trim(),
            };
            if (!payload.authorName || !payload.content) {
              setCommentStatus('請填寫名稱與留言內容', true);
              return;
            }

            isSubmittingComment = true;
            submitBtn.disabled = true;
            setCommentStatus('送出中...', false);
            try {
              const response = await fetch('/api/comments', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
              });
              const data = await response.json();
              if (!response.ok) {
                setCommentStatus(data.error || '留言送出失敗', true);
                return;
              }
              try {
                localStorage.setItem(storageKey, JSON.stringify({
                  authorName: payload.authorName,
                  authorSiteSlug: payload.authorSiteSlug,
                }));
              } catch {}

              const createdComment = data && data.comment
                ? data.comment
                : {
                  authorName: payload.authorName,
                  authorSiteSlug: payload.authorSiteSlug,
                  content: payload.content,
                  createdAt: new Date().toISOString(),
                };
              addCommentToList(createdComment);
              bumpCommentCount();
              contentInput.value = '';
              contentInput.focus();
              setCommentStatus('留言成功，已更新列表。', false);
            } catch (error) {
              setCommentStatus(error.message || '留言送出失敗', true);
            } finally {
              isSubmittingComment = false;
              submitBtn.disabled = false;
            }
          });
        }
      })();
    </script>
  `,
    siteConfig.colorTheme || "default",
    siteConfig.customCss || ""
  );
}

export function renderAdminPage(site, siteConfig, authed, baseDomain) {
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
    `, siteConfig.colorTheme || 'default'
    );
  }

  return renderLayout(
    `${site.displayName} Admin`,
    String.raw`
    <section class="panel wide admin-shell">
      <header class="site-header">
        <div>
          <p class="eyebrow">editor</p>
          <h1>${escapeHtml(siteConfig.heroTitle || site.displayName)}</h1>
          <p class="muted">${escapeHtml(site.slug)}.${escapeHtml(baseDomain)}</p>
        </div>
        <div class="row-actions">
          <a class="link-button" href="/" target="_blank" rel="noreferrer noopener">Frontend</a>
          <button id="new-post" class="link-button" type="button">New</button>
          <button id="logout" class="link-button" type="button">Logout</button>
          <a class="link-button" href="/api/export">Export</a>
          <a class="link-button" href="https://blog.bdfz.net/" target="_blank" rel="noreferrer noopener">Project</a>
        </div>
      </header>

      <nav class="admin-tabs">
        <button id="tab-posts" class="admin-tab active" type="button">✏️ Posts</button>
        <button id="tab-settings" class="admin-tab" type="button">⚙️ Settings</button>
      </nav>

      <!-- ═══ POSTS TAB ═══ -->
      <div id="panel-posts" class="admin-panel">
        <div class="admin-grid">
          <aside class="admin-list">
            <p class="muted">My Posts</p>
            <input id="post-filter" placeholder="搜尋標題或 slug..." />
            <p id="post-count" class="muted">0 篇</p>
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
            <div class="md-toolbar">
              <button type="button" data-md="h1" title="Heading 1">H1</button>
              <button type="button" data-md="bold" title="Bold">B</button>
              <button type="button" data-md="italic" title="Italic">I</button>
              <button type="button" data-md="code" title="Code">&#96;</button>
              <button type="button" data-md="heading" title="Heading">H2</button>
              <button type="button" data-md="h3" title="Heading 3">H3</button>
              <button type="button" data-md="link" title="Link">🔗</button>
              <button type="button" data-md="image" title="Image">🖼</button>
              <button type="button" data-md="list" title="List">•</button>
              <button type="button" data-md="task" title="Task list">☑︎</button>
              <button type="button" data-md="ordered" title="Ordered list">1.</button>
              <button type="button" data-md="quote" title="Quote">❝</button>
              <button type="button" data-md="table" title="Table">▦</button>
              <button type="button" data-md="math-inline" title="Inline KaTeX">∑</button>
              <button type="button" data-md="math-block" title="Block KaTeX">$$</button>
              <button type="button" data-md="br" title="Line break">↵</button>
              <button type="button" data-md="codeblock" title="Code block">{ }</button>
              <button type="button" data-md="hr" title="Divider">—</button>
              <button type="button" id="fullscreen-toggle" class="fullscreen-btn">⛶ 全屏</button>
            </div>
            <textarea id="content" placeholder="# Start writing..."></textarea>
            <div class="row-actions">
              <button id="save" type="button">發佈 / 更新</button>
              <a id="preview" class="link-button" href="#" target="_blank" rel="noreferrer noopener">預覽</a>
              <button id="delete-post" type="button" class="link-button danger-ghost">刪除文章</button>
            </div>
            <p id="editor-status" class="muted"></p>
            <section class="comment-admin-panel">
              <h3>留言管理（目前文章）</h3>
              <ul id="comment-admin-list" class="comment-list compact"></ul>
              <p id="comment-admin-status" class="muted"></p>
            </section>
          </section>
        </div>
      </div>

      <!-- ═══ SETTINGS TAB ═══ -->
      <div id="panel-settings" class="admin-panel" style="display:none">
        <div class="settings-grid">
          <section class="settings-form">
            <h2>站點設定</h2>
            <label>顯示名稱</label>
            <input id="siteDisplayName" maxlength="60" />
            <label>站點簡介</label>
            <input id="siteDescription" maxlength="240" />
            <label>首頁標題</label>
            <input id="siteHeroTitle" maxlength="120" />
            <label>首頁副標</label>
            <input id="siteHeroSubtitle" maxlength="240" />
            <label>主題色系</label>
            <select id="siteColorTheme" style="font:inherit;border-radius:10px;border:1px solid var(--line);background:rgba(255,255,255,.65);padding:.65rem .78rem;color:var(--ink);font-family:var(--font-mono);font-size:.92rem;">
              <option value="default">預設 / 棕色 (Brown)</option>
              <option value="ocean">大海 / 湖藍 (Ocean)</option>
              <option value="forest">森林 / 墨綠 (Forest)</option>
              <option value="violet">紫羅蘭 / 淡紫 (Violet)</option>
              <option value="sunset">晚霞 / 赭紅 (Sunset)</option>
              <option value="mint">薄荷 / 青綠 (Mint)</option>
              <option value="graphite">石墨 / 藍灰 (Graphite)</option>
            </select>
            <label>頁尾文字</label>
            <input id="siteFooterNote" maxlength="240" />
            <label>自訂 CSS（前台）</label>
            <textarea id="siteCustomCss" class="small-textarea" maxlength="8000" placeholder=".article-body h2 { letter-spacing: 0.02em; }"></textarea>
            <p class="muted">僅作用於你的前台頁面（首頁與文章頁）。</p>
            <label>外部連結（每行：標題|https://url）</label>
            <textarea id="siteHeaderLinks" class="small-textarea" placeholder="作品集|https://example.com"></textarea>
            <label class="inline-check">
              <input id="siteHideCommunitySites" type="checkbox" />
              隱藏「同學新站」板塊
            </label>
            <label class="inline-check">
              <input id="siteHideCampusFeed" type="checkbox" />
              隱藏「全校最新文章」板塊
            </label>
            <label class="inline-check">
              <input id="siteCommentsEnabled" type="checkbox" />
              啟用文章留言
            </label>
            <button id="save-settings" type="button">儲存站點設定</button>
            <p id="settings-status" class="muted"></p>
          </section>
          <aside class="settings-aside">
            <h3>匯入</h3>
            <p class="muted">從 BearBlog 匯入 CSV</p>
            <input id="import-file" type="file" accept=".csv" />
            <button id="import-btn" type="button">匯入</button>
            <p id="import-status" class="muted"></p>
          </aside>
        </div>
      </div>
    </section>

    <script>
      const initialConfig = ${toScriptJson(siteConfig)};
      const state = {
        currentSlug: '',
        posts: [],
        comments: [],
        postFilter: '',
        siteConfig: initialConfig,
      };

      const postList = document.getElementById('post-list');
      const postFilterInput = document.getElementById('post-filter');
      const postCountEl = document.getElementById('post-count');
      const siteDisplayNameInput = document.getElementById('siteDisplayName');
      const siteDescriptionInput = document.getElementById('siteDescription');
      const siteHeroTitleInput = document.getElementById('siteHeroTitle');
      const siteHeroSubtitleInput = document.getElementById('siteHeroSubtitle');
      const siteColorThemeInput = document.getElementById('siteColorTheme');
      const siteFooterNoteInput = document.getElementById('siteFooterNote');
      const siteCustomCssInput = document.getElementById('siteCustomCss');
      const siteHeaderLinksInput = document.getElementById('siteHeaderLinks');
      const siteHideCommunitySitesInput = document.getElementById('siteHideCommunitySites');
      const siteHideCampusFeedInput = document.getElementById('siteHideCampusFeed');
      const siteCommentsEnabledInput = document.getElementById('siteCommentsEnabled');
      const titleInput = document.getElementById('title');
      const postSlugInput = document.getElementById('postSlug');
      const descriptionInput = document.getElementById('description');
      const publishedInput = document.getElementById('published');
      const contentInput = document.getElementById('content');
      const statusEl = document.getElementById('editor-status');
      const settingsStatusEl = document.getElementById('settings-status');
      const commentAdminListEl = document.getElementById('comment-admin-list');
      const commentAdminStatusEl = document.getElementById('comment-admin-status');
      const previewLink = document.getElementById('preview');
      const deletePostBtn = document.getElementById('delete-post');
      let savingPost = false;
      let savingSettings = false;
      let importingPosts = false;
      let loadPostToken = 0;
      let baselineState = '';

      function setStatus(message, isError = false) {
        statusEl.textContent = message;
        statusEl.style.color = isError ? '#ae3a22' : '#6b6357';
      }

      function setSettingsStatus(message, isError = false) {
        if (!settingsStatusEl) {
          return;
        }
        settingsStatusEl.textContent = message;
        settingsStatusEl.style.color = isError ? '#ae3a22' : '#6b6357';
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
  if (siteColorThemeInput) siteColorThemeInput.value = safe.colorTheme || 'default';
  siteFooterNoteInput.value = safe.footerNote || '';
  if (siteCustomCssInput) siteCustomCssInput.value = safe.customCss || '';
  siteHeaderLinksInput.value = renderHeaderLinksValue(safe.headerLinks || []);
  if (siteHideCommunitySitesInput) siteHideCommunitySitesInput.checked = !!safe.hideCommunitySites;
  if (siteHideCampusFeedInput) siteHideCampusFeedInput.checked = !!safe.hideCampusFeed;
  if (siteCommentsEnabledInput) siteCommentsEnabledInput.checked = safe.commentsEnabled !== false;
}

function draftKey(slug) {
  const id = slug || 'new';
  return 'stublogs-draft:' + location.host + ':' + id;
}

function getEditorSnapshot() {
  return JSON.stringify({
    title: titleInput.value,
    postSlug: postSlugInput.value,
    description: descriptionInput.value,
    content: contentInput.value,
    published: publishedInput.checked,
  });
}

function markBaseline() {
  baselineState = getEditorSnapshot();
}

function hasUnsavedChanges() {
  return baselineState && baselineState !== getEditorSnapshot();
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
  if (previewLink) {
    const exists = slug && (state.currentSlug === slug || state.posts.some((post) => post.postSlug === slug));
    previewLink.href = exists ? '/preview/' + encodeURIComponent(slug) : '#';
    previewLink.setAttribute('aria-disabled', exists ? 'false' : 'true');
  }
}

function resetEditor() {
  state.currentSlug = '';
  titleInput.value = '';
  postSlugInput.value = '';
  descriptionInput.value = '';
  publishedInput.checked = true;
  contentInput.value = '';
  if (typeof updateSaveBtn === 'function') updateSaveBtn();
  syncPreview();
  state.comments = [];
  renderCommentAdminList();
  setCommentAdminStatus('');
  if (deletePostBtn) deletePostBtn.disabled = true;
  setStatus('New post');
  markBaseline();
  tryRestoreDraft('');
}

function renderPostList() {
  if (!state.posts.length) {
    postList.innerHTML = '<li class="muted">No posts yet</li>';
    if (postCountEl) postCountEl.textContent = '0 篇';
    return;
  }

  const keyword = String(state.postFilter || '').trim().toLowerCase();
  const filtered = keyword
    ? state.posts.filter((post) => {
      const text = (post.title + ' ' + post.postSlug).toLowerCase();
      return text.includes(keyword);
    })
    : state.posts;

  if (postCountEl) {
    postCountEl.textContent = keyword
      ? ('共 ' + state.posts.length + ' 篇，顯示 ' + filtered.length + ' 篇')
      : (state.posts.length + ' 篇');
  }

  if (!filtered.length) {
    postList.innerHTML = '<li class="muted">沒有符合搜尋的文章</li>';
    return;
  }

  postList.innerHTML = filtered
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
      const targetSlug = button.getAttribute('data-slug');
      if (!targetSlug || targetSlug === state.currentSlug) {
        return;
      }
      if (hasUnsavedChanges() && !confirm('目前有未儲存內容，確定切換文章？')) {
        return;
      }
      loadPost(targetSlug);
    });
  });
}

function setCommentAdminStatus(message, isError = false) {
  if (!commentAdminStatusEl) {
    return;
  }
  commentAdminStatusEl.textContent = message;
  commentAdminStatusEl.style.color = isError ? '#ae3a22' : '#6b6357';
}

function renderCommentAdminList() {
  if (!commentAdminListEl) {
    return;
  }
  if (!state.currentSlug) {
    commentAdminListEl.innerHTML = '<li class="muted">請先選擇文章。</li>';
    return;
  }
  if (!state.comments.length) {
    commentAdminListEl.innerHTML = '<li class="muted">此文章目前沒有留言。</li>';
    return;
  }

  commentAdminListEl.innerHTML = state.comments
    .map((comment) => {
      const authorSite = comment.authorSiteSlug
        ? '<small class="muted"> · ' + escapeText(comment.authorSiteSlug) + '.bdfz.net</small>'
        : '';
      const createdAt = comment.createdAt
        ? new Date(comment.createdAt).toLocaleString()
        : '';
      return '<li class="comment-item" data-comment-id="' + comment.id + '">' +
        '<p class="comment-meta">' + escapeText(comment.authorName) + authorSite + ' · ' + escapeText(createdAt) + '</p>' +
        '<p class="comment-content">' + escapeText(comment.content || '').replace(/\n/g, '<br />') + '</p>' +
        '<button type="button" class="comment-delete-btn" data-comment-id="' + comment.id + '">刪除留言</button>' +
      '</li>';
    })
    .join('');
}

async function refreshCommentsForCurrentPost() {
  if (!state.currentSlug) {
    state.comments = [];
    renderCommentAdminList();
    return;
  }
  setCommentAdminStatus('載入留言中...');
  try {
    const payload = await fetchJson('/api/admin/comments?postSlug=' + encodeURIComponent(state.currentSlug));
    state.comments = payload.comments || [];
    renderCommentAdminList();
    setCommentAdminStatus('留言載入完成');
  } catch (error) {
    setCommentAdminStatus(error.message || '留言載入失敗', true);
  }
}

async function fetchJson(path, options) {
  const response = await fetch(path, options);
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    if (response.status === 401) {
      throw new Error('登入已過期，請重新登入');
    }
    throw new Error((payload && payload.error) || ('Request failed (' + response.status + ')'));
  }
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid server response');
  }
  return payload;
}

async function refreshPosts() {
  const payload = await fetchJson('/api/list-posts?includeDrafts=1');
  state.posts = payload.posts || [];
  if (state.currentSlug && !state.posts.some((post) => post.postSlug === state.currentSlug)) {
    state.currentSlug = '';
    if (deletePostBtn) deletePostBtn.disabled = true;
  }
  renderPostList();
  if (!state.currentSlug && state.posts.length) {
    loadPost(state.posts[0].postSlug).catch((error) => {
      setStatus(error.message || 'Failed to load first post', true);
    });
  } else if (!state.posts.length && deletePostBtn) {
    deletePostBtn.disabled = true;
  }
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

  const token = ++loadPostToken;
  try {
    const payload = await fetchJson('/api/posts/' + encodeURIComponent(slug));
    if (token !== loadPostToken) {
      return;
    }
    const post = payload.post;
    state.currentSlug = post.postSlug;
    titleInput.value = post.title || '';
    postSlugInput.value = post.postSlug || '';
    descriptionInput.value = post.description || '';
    publishedInput.checked = Number(post.published) === 1;
    contentInput.value = post.content || '';
    if (deletePostBtn) deletePostBtn.disabled = false;
    if (typeof updateSaveBtn === 'function') updateSaveBtn();
    renderPostList();
    tryRestoreDraft(post.postSlug);
    markBaseline();
    await refreshCommentsForCurrentPost();
    setStatus('Loaded ' + post.postSlug);
  } catch (error) {
    if (deletePostBtn) deletePostBtn.disabled = true;
    setStatus(error.message || 'Failed to load post', true);
  }
}

async function savePost() {
  if (savingPost) {
    return;
  }
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
  savingPost = true;
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.textContent = '儲存中...';
  }

  try {
    const payload = await fetchJson('/api/posts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        postSlug,
        previousSlug: state.currentSlug || null,
        description: descriptionInput.value.trim(),
        content: contentInput.value,
        published: publishedInput.checked,
      }),
    });

    state.currentSlug = payload.post.postSlug;
    postSlugInput.value = payload.post.postSlug;
    syncPreview();
    await refreshPosts();
    await refreshCommentsForCurrentPost();
    if (publishedInput.checked) {
      setStatus('已發佈：' + new Date().toLocaleTimeString());
    } else {
      setStatus('已儲存草稿（前台不顯示）');
    }
    markBaseline();
    saveDraft();
  } catch (error) {
    setStatus(error.message || 'Save failed', true);
  } finally {
    savingPost = false;
    if (saveBtn) {
      saveBtn.disabled = false;
    }
    updateSaveBtn();
  }
}

async function saveSiteSettings() {
  if (savingSettings) {
    return;
  }
  savingSettings = true;
  setSettingsStatus('儲存設定中...');
  if (saveSettingsBtn) {
    saveSettingsBtn.disabled = true;
    saveSettingsBtn.textContent = '儲存中...';
  }
  try {
    const payload = await fetchJson('/api/site-settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        displayName: siteDisplayNameInput.value.trim(),
        description: siteDescriptionInput.value.trim(),
        heroTitle: siteHeroTitleInput.value.trim(),
        heroSubtitle: siteHeroSubtitleInput.value.trim(),
        colorTheme: siteColorThemeInput.value,
        footerNote: siteFooterNoteInput.value.trim(),
        customCss: siteCustomCssInput ? siteCustomCssInput.value : '',
        headerLinks: parseHeaderLinks(siteHeaderLinksInput.value),
        hideCommunitySites: siteHideCommunitySitesInput.checked,
        hideCampusFeed: siteHideCampusFeedInput.checked,
        commentsEnabled: siteCommentsEnabledInput.checked,
      }),
    });

    state.siteConfig = payload.config || state.siteConfig;
    applySettingsToForm(state.siteConfig);
    if (typeof window.__applyThemeDockTheme === 'function') {
      window.__applyThemeDockTheme(state.siteConfig.colorTheme || 'default');
    } else {
      document.body.className = "theme-" + (state.siteConfig.colorTheme || "default");
    }
    setSettingsStatus('站點設定已儲存');
  } catch (error) {
    setSettingsStatus(error.message || '儲存站點設定失敗', true);
  } finally {
    savingSettings = false;
    if (saveSettingsBtn) {
      saveSettingsBtn.disabled = false;
      saveSettingsBtn.textContent = '儲存站點設定';
    }
  }
}

document.getElementById('new-post').addEventListener('click', () => {
  if (hasUnsavedChanges() && !confirm('目前有未儲存內容，確定建立新文章？')) {
    return;
  }
  resetEditor();
});
document.getElementById('save').addEventListener('click', savePost);
document.getElementById('save-settings').addEventListener('click', saveSiteSettings);
document.getElementById('logout').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  location.reload();
});

if (commentAdminListEl) {
  commentAdminListEl.addEventListener('click', async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    const commentId = target.getAttribute('data-comment-id');
    if (!commentId || !target.classList.contains('comment-delete-btn')) {
      return;
    }
    if (!confirm('確認刪除此留言？')) {
      return;
    }
    setCommentAdminStatus('刪除留言中...');
    try {
      await fetchJson('/api/comments/' + encodeURIComponent(commentId), { method: 'DELETE' });
      await refreshCommentsForCurrentPost();
      setCommentAdminStatus('留言已刪除');
    } catch (error) {
      setCommentAdminStatus(error.message || '刪除留言失敗', true);
    }
  });
}

if (deletePostBtn) {
  deletePostBtn.disabled = true;
  deletePostBtn.addEventListener('click', async () => {
    if (!state.currentSlug) {
      setStatus('請先選擇文章', true);
      return;
    }
    const slugToDelete = state.currentSlug;
    const ok = confirm('確認刪除文章 ' + slugToDelete + '？此操作不可復原。');
    if (!ok) {
      return;
    }

    deletePostBtn.disabled = true;
    setStatus('刪除中...');
    try {
      await fetchJson('/api/posts/' + encodeURIComponent(slugToDelete), { method: 'DELETE' });
      const idx = state.posts.findIndex((post) => post.postSlug === slugToDelete);
      state.posts = state.posts.filter((post) => post.postSlug !== slugToDelete);
      renderPostList();
      setStatus('已刪除：' + slugToDelete);
      state.currentSlug = '';
      state.comments = [];
      renderCommentAdminList();

      if (state.posts.length) {
        const next = state.posts[Math.max(0, idx - 1)] || state.posts[0];
        if (next && next.postSlug) {
          await loadPost(next.postSlug);
        }
      } else {
        resetEditor();
      }
    } catch (error) {
      setStatus(error.message || '刪除失敗', true);
      deletePostBtn.disabled = false;
    }
  });
}

titleInput.addEventListener('blur', () => {
  if (!postSlugInput.value.trim()) {
    postSlugInput.value = toSlug(titleInput.value);
  }
  syncPreview();
});

postSlugInput.addEventListener('input', () => {
  postSlugInput.value = toSlug(postSlugInput.value);
  syncPreview();
});

if (previewLink) {
  previewLink.addEventListener('click', (event) => {
    if (previewLink.getAttribute('aria-disabled') === 'true') {
      event.preventDefault();
      setStatus('請先儲存文章後再預覽', true);
    }
  });
}

if (postFilterInput) {
  postFilterInput.addEventListener('input', () => {
    state.postFilter = postFilterInput.value;
    renderPostList();
  });
}

contentInput.addEventListener('input', saveDraft);
titleInput.addEventListener('input', saveDraft);
descriptionInput.addEventListener('input', saveDraft);

const saveBtn = document.getElementById('save');
const saveSettingsBtn = document.getElementById('save-settings');
function updateSaveBtn() {
  if (!saveBtn) {
    return;
  }
  saveBtn.textContent = publishedInput.checked ? '發佈 / 更新 (⌘S)' : '儲存草稿 (⌘S)';
}
publishedInput.addEventListener('change', () => {
  saveDraft();
  updateSaveBtn();
});
updateSaveBtn();

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

window.addEventListener('beforeunload', (event) => {
  if (!hasUnsavedChanges()) {
    return;
  }
  event.preventDefault();
  event.returnValue = '';
});

applySettingsToForm(initialConfig);
resetEditor();
refreshSettings().catch((error) => {
  setSettingsStatus(error.message || 'Failed to load site settings', true);
});
refreshPosts().catch((error) => {
  setStatus(error.message || 'Failed to load posts', true);
});

// ── Tab switching ──
const tabPosts = document.getElementById('tab-posts');
const tabSettings = document.getElementById('tab-settings');
const panelPosts = document.getElementById('panel-posts');
const panelSettings = document.getElementById('panel-settings');
if (tabPosts && tabSettings) {
  tabPosts.addEventListener('click', () => {
    tabPosts.classList.add('active');
    tabSettings.classList.remove('active');
    panelPosts.style.display = '';
    panelSettings.style.display = 'none';
  });
  tabSettings.addEventListener('click', () => {
    tabSettings.classList.add('active');
    tabPosts.classList.remove('active');
    panelSettings.style.display = '';
    panelPosts.style.display = 'none';
  });
}

// ── Markdown toolbar ──
function insertMd(type) {
  const ta = contentInput;
  const start = ta.selectionStart;
  const end = ta.selectionEnd;
  const sel = ta.value.substring(start, end);
  const tick = String.fromCharCode(96);
  const fence = tick + tick + tick;
  const lines = (sel || '').split('\n');
  let replacement = '';

  const wrapSelection = (before, after, fallback = '') =>
    before + (sel || fallback) + after;
  const mapLines = (transform, fallback = '') =>
    (sel || fallback)
      .split('\n')
      .map((line, index) => transform(line, index))
      .join('\n');

  switch (type) {
    case 'h1':
      replacement = wrapSelection('# ', '', '標題');
      break;
    case 'heading':
      replacement = wrapSelection('## ', '', '標題');
      break;
    case 'h3':
      replacement = wrapSelection('### ', '', '標題');
      break;
    case 'bold':
      replacement = wrapSelection('**', '**', '文字');
      break;
    case 'italic':
      replacement = wrapSelection('*', '*', '文字');
      break;
    case 'code':
      replacement = sel.includes('\n')
        ? '\n' + fence + '\n' + (sel || 'code') + '\n' + fence + '\n'
        : tick + (sel || 'code') + tick;
      break;
    case 'codeblock':
      replacement = '\n' + fence + '\n' + (sel || 'code') + '\n' + fence + '\n';
      break;
    case 'link':
      replacement = '[' + (sel || '連結文字') + '](https://)';
      break;
    case 'image':
      replacement = '![' + (sel || '圖片描述') + '](https://)';
      break;
    case 'list':
      replacement = mapLines((line) => '- ' + (line || '列表項'), '列表項');
      break;
    case 'task':
      replacement = mapLines((line) => '- [ ] ' + (line || '待辦事項'), '待辦事項');
      break;
    case 'ordered':
      replacement = mapLines((line, index) => (index + 1) + '. ' + (line || '列表項'), '列表項');
      break;
    case 'quote':
      replacement = mapLines((line) => '> ' + (line || '引用文字'), '引用文字');
      break;
    case 'table':
      replacement = '\n| 欄位1 | 欄位2 |\n| --- | --- |\n| 內容1 | 內容2 |\n';
      break;
    case 'math-inline':
      replacement = '$' + (sel || 'x^2+y^2=z^2') + '$';
      break;
    case 'math-block':
      replacement = '\n$$\n' + (sel || '\\int_0^1 x^2 \\, dx') + '\n$$\n';
      break;
    case 'br':
      replacement = sel
        ? lines.join('  \n')
        : '第一行  \n第二行';
      break;
    case 'hr':
      replacement = '\n---\n';
      break;
    default:
      replacement = sel;
      break;
  }

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
    if (importingPosts) {
      return;
    }
    const file = importFile.files[0];
    if (!file) {
      importStatus.textContent = 'Please select a CSV file';
      return;
    }
    importingPosts = true;
    importStatus.textContent = 'Importing...';
    importBtn.disabled = true;
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch('/api/import', { method: 'POST', body: fd });
      let data = null;
      try {
        data = await res.json();
      } catch {
        data = null;
      }
      if (!res.ok) {
        importStatus.textContent = (data && data.error) || 'Import failed';
        importStatus.style.color = 'var(--accent)';
        return;
      }
      importStatus.textContent = 'Imported ' + data.imported + ', skipped ' + data.skipped + ', errors ' + data.errors;
      importStatus.style.color = '';
      await refreshPosts();
    } catch (e) {
      importStatus.textContent = e.message || 'Import failed';
    } finally {
      importingPosts = false;
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

function renderThemeControlDock(mode = "front") {
  return `
  <section id="theme-dock" class="theme-dock" data-mode="${escapeHtml(mode)}">
    <label for="theme-dock-select">頁面色系</label>
    <select id="theme-dock-select" aria-label="頁面色系">
      <option value="default">Default</option>
      <option value="ocean">Ocean</option>
      <option value="forest">Forest</option>
      <option value="violet">Violet</option>
      <option value="sunset">Sunset</option>
      <option value="mint">Mint</option>
      <option value="graphite">Graphite</option>
    </select>
    <label for="contrast-dock-select">文字對比</label>
    <select id="contrast-dock-select" aria-label="文字對比">
      <option value="normal">標準</option>
      <option value="soft">柔和</option>
      <option value="strong">高對比</option>
    </select>
  </section>
  `;
}

function renderLayout(title, body, colorTheme = 'default', customCss = "") {
  const safeCustomCss = customCss
    ? `\n/* user custom css */\n${escapeStyleTagContent(customCss)}\n`
    : "";
  return `<!doctype html>
<html lang="zh-Hant">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500;600&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css" />
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
.theme-ocean{--bg-1:#e9f3fb;--bg-2:#d9e9f8;--ink:#173042;--ink-2:#274459;--muted:#59768f;--panel:rgba(247,252,255,.92);--line:rgba(34,74,112,.18);--accent:#0a6fab;--accent-glow:rgba(10,111,171,.16);--code-bg:rgba(10,111,171,.1)}
.theme-forest{--bg-1:#ebf4ef;--bg-2:#dcece3;--ink:#1f3329;--ink-2:#2d483b;--muted:#62786b;--panel:rgba(246,252,248,.92);--line:rgba(45,88,67,.18);--accent:#2f6c4b;--accent-glow:rgba(47,108,75,.16);--code-bg:rgba(47,108,75,.1)}
.theme-violet{--bg-1:#f3effa;--bg-2:#e8def7;--ink:#2f2440;--ink-2:#3f3056;--muted:#6b5f83;--panel:rgba(252,248,255,.92);--line:rgba(77,56,117,.16);--accent:#7248b5;--accent-glow:rgba(114,72,181,.16);--code-bg:rgba(114,72,181,.1)}
.theme-sunset{--bg-1:#f9eee7;--bg-2:#f2dfd3;--ink:#3b2418;--ink-2:#563627;--muted:#866450;--panel:rgba(255,249,245,.92);--line:rgba(128,74,49,.18);--accent:#b85b31;--accent-glow:rgba(184,91,49,.16);--code-bg:rgba(184,91,49,.1)}
.theme-mint{--bg-1:#e8f6f2;--bg-2:#d6eee7;--ink:#17352f;--ink-2:#245048;--muted:#5d7f77;--panel:rgba(245,253,250,.92);--line:rgba(37,100,88,.18);--accent:#22826f;--accent-glow:rgba(34,130,111,.16);--code-bg:rgba(34,130,111,.1)}
.theme-graphite{--bg-1:#edf0f5;--bg-2:#dfe5ee;--ink:#202936;--ink-2:#313d4d;--muted:#677180;--panel:rgba(248,251,255,.92);--line:rgba(61,79,103,.18);--accent:#4f6688;--accent-glow:rgba(79,102,136,.18);--code-bg:rgba(79,102,136,.1)}
.contrast-soft{--ink:#4a473f;--ink-2:#5b554b;--muted:#7b7467}
.contrast-strong{--ink:#1c1812;--ink-2:#2a241c;--muted:#4d473d}
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
  .theme-ocean{--bg-1:#0b1520;--bg-2:#122131;--ink:#c8ddf0;--ink-2:#acc8df;--muted:#7e97ad;--panel:rgba(15,29,44,.92);--line:rgba(102,162,224,.15);--accent:#5aaef6;--accent-glow:rgba(90,174,246,.18);--code-bg:rgba(90,174,246,.13)}
  .theme-forest{--bg-1:#0f1815;--bg-2:#14241d;--ink:#cae3d8;--ink-2:#aed4c5;--muted:#83a698;--panel:rgba(18,33,28,.92);--line:rgba(101,166,133,.14);--accent:#6ab58f;--accent-glow:rgba(106,181,143,.18);--code-bg:rgba(106,181,143,.13)}
  .theme-violet{--bg-1:#15111c;--bg-2:#21182d;--ink:#ded2f0;--ink-2:#c3b4de;--muted:#9f8fb9;--panel:rgba(32,23,44,.92);--line:rgba(152,121,215,.14);--accent:#a782e0;--accent-glow:rgba(167,130,224,.2);--code-bg:rgba(167,130,224,.14)}
  .theme-sunset{--bg-1:#1d120f;--bg-2:#291915;--ink:#f0d2c6;--ink-2:#dfbaa9;--muted:#b08a79;--panel:rgba(43,26,21,.92);--line:rgba(199,128,96,.14);--accent:#ed946f;--accent-glow:rgba(237,148,111,.2);--code-bg:rgba(237,148,111,.14)}
  .theme-mint{--bg-1:#0d1917;--bg-2:#112824;--ink:#c7ebe3;--ink-2:#abd8cd;--muted:#80a89e;--panel:rgba(17,35,31,.92);--line:rgba(106,190,171,.14);--accent:#74cdb7;--accent-glow:rgba(116,205,183,.2);--code-bg:rgba(116,205,183,.14)}
  .theme-graphite{--bg-1:#11151b;--bg-2:#181f29;--ink:#d3dbe8;--ink-2:#b4c0d0;--muted:#8592a3;--panel:rgba(24,33,43,.92);--line:rgba(131,154,188,.14);--accent:#95aaca;--accent-glow:rgba(149,170,202,.2);--code-bg:rgba(149,170,202,.14)}
  .contrast-soft{--ink:#b6c0ce;--ink-2:#9ca7b7;--muted:#7f8998}
  .contrast-strong{--ink:#ecf2fb;--ink-2:#d2dced;--muted:#a8b3c2}
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
.link-button[aria-disabled="true"]{opacity:.45;pointer-events:auto;filter:none}
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
.pager{display:flex;align-items:center;gap:.8rem;margin-top:1rem;flex-wrap:wrap}
.pager a{text-decoration:none;border:1px solid var(--line);padding:.3rem .7rem;border-radius:999px;color:var(--ink);transition:all .2s}
.pager a:hover{border-color:var(--accent);color:var(--accent)}
.pager a.disabled{opacity:.4;pointer-events:none}
.preview-badge{display:inline-block;margin-left:.4rem;padding:.1rem .4rem;border-radius:999px;border:1px solid var(--line);font-size:.7rem;letter-spacing:.04em}
.theme-dock{display:flex;flex-wrap:wrap;align-items:center;gap:.45rem;margin:.8rem 0;padding:.55rem;border:1px solid var(--line);border-radius:12px;background:var(--code-bg)}
.theme-dock label{font-size:.74rem;margin-right:.15rem}
.theme-dock select{min-width:124px;max-width:100%;padding:.35rem .45rem;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);font-family:var(--font-mono);font-size:.8rem}
/* article */
.article-body{line-height:1.78;font-size:1.05rem}
.article-body h2,.article-body h3,.article-body h4{margin-top:1.6rem}
.article-body p{margin:.8rem 0}
.article-body hr{border:none;border-top:1px dashed var(--line);margin:1.2rem 0}
.article-body blockquote{border-left:3px solid var(--accent);padding:.5rem 0 .5rem 1rem;margin:1rem 0;color:var(--muted);background:var(--accent-glow);border-radius:0 8px 8px 0}
.article-body ul,.article-body ol{padding-left:1.4rem;margin:.6rem 0}
.article-body del{opacity:.75}
.article-body img{max-width:100%;border-radius:8px;margin:.8rem 0}
.article-wrap{display:grid;grid-template-columns:minmax(0,1fr) 240px;gap:1.2rem}
.article-side{border-left:1px solid var(--line);padding-left:.9rem}
.article-body pre{background:rgba(30,28,24,.96);color:#e8e4dc;padding:1rem;border-radius:10px;overflow-x:auto;font-size:.88rem;line-height:1.5;margin:.8rem 0}
@media(prefers-color-scheme:dark){.article-body pre{background:rgba(255,255,255,.05);border:1px solid var(--line)}}
.article-body code{background:var(--code-bg);padding:.12rem .35rem;border-radius:4px;font-size:.88em;font-family:var(--font-mono)}
.article-body pre code{background:none;padding:0;font-size:inherit}
.article-body .katex-display{overflow-x:auto;overflow-y:hidden;padding:.2rem 0}
.article-body .katex{max-width:100%}
.article-body .katex-display > .katex{max-width:100%}
.read-time{font-family:var(--font-mono);font-size:.78rem;color:var(--muted);margin-left:.5rem}
.comment-panel{margin-top:1rem}
.comment-list{list-style:none;margin:1rem 0 0;padding:0;display:grid;gap:.75rem}
.comment-list.compact{gap:.5rem}
.comment-item{border:1px solid var(--line);background:rgba(255,255,255,.48);border-radius:10px;padding:.65rem .75rem}
@media(prefers-color-scheme:dark){.comment-item{background:rgba(255,255,255,.03)}}
.comment-meta{font-family:var(--font-mono);font-size:.76rem;color:var(--muted);margin-bottom:.28rem}
.comment-content{white-space:normal;overflow-wrap:anywhere}
.comment-delete-btn{margin-top:.45rem;background:transparent;color:var(--muted);border:1px solid var(--line);padding:.36rem .62rem;min-height:34px}
.comment-delete-btn:hover{color:var(--accent);border-color:var(--accent);transform:none}
.comments-pager{margin-top:.35rem}
/* back to top */
.back-top{position:fixed;bottom:1.5rem;right:1.5rem;width:42px;height:42px;border-radius:50%;background:var(--accent);color:#fff;border:none;font-size:1.1rem;cursor:pointer;opacity:0;transform:translateY(10px);transition:all .25s;z-index:100;display:flex;align-items:center;justify-content:center}
.back-top.visible{opacity:1;transform:translateY(0)}
/* admin */
.admin-shell{display:grid;gap:1rem}
.admin-tabs{display:flex;gap:.4rem;border-bottom:2px solid var(--line);padding-bottom:0}
.admin-tab{background:transparent;color:var(--muted);border:none;border-bottom:2px solid transparent;border-radius:0;padding:.6rem 1.2rem;font-family:var(--font-mono);font-size:.85rem;margin-bottom:-2px;transition:all .2s}
.admin-tab:hover{color:var(--ink);transform:none}
.admin-tab.active{color:var(--accent);border-bottom-color:var(--accent);font-weight:600}
.admin-panel{margin-top:1rem}
.admin-grid{display:grid;grid-template-columns:220px minmax(0,1fr);gap:1.5rem}
.admin-list{border-right:1px solid var(--line);padding-right:1rem;display:grid;gap:.5rem;align-content:start;min-width:0}
.admin-list ul{list-style:none;margin:0;padding:0;display:grid;gap:.4rem;max-height:min(72vh,780px);overflow:auto;padding-right:.25rem}
.danger-ghost{background:transparent;color:var(--muted);border-color:var(--line)}
.danger-ghost:hover{color:#b7462c;border-color:#b7462c;transform:none}
.settings-grid{display:grid;grid-template-columns:1fr 280px;gap:2rem}
.settings-grid > *{min-width:0}
.settings-form{display:grid;gap:.5rem;align-content:start}
.settings-aside{border-left:1px solid var(--line);padding-left:1.5rem;display:grid;gap:.5rem;align-content:start}
.settings-aside input[type="file"]{max-width:100%;width:100%;min-width:0}
.settings-aside #import-btn{width:100%}
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
.comment-admin-panel{margin-top:.8rem;display:grid;gap:.5rem}
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
  .admin-list ul{max-height:none}
  .settings-grid{grid-template-columns:1fr}
  .settings-aside{border-left:0;border-top:1px solid var(--line);padding-left:0;padding-top:1rem}
  .site-header{flex-direction:column;align-items:stretch}
  .site-header .row-actions{width:100%}
  .site-header .row-actions .link-button,
  .site-header .row-actions button{flex:1}
  .community-grid{grid-template-columns:1fr}
  .community-panel{border-left:0;border-top:1px solid var(--line);padding-left:0;padding-top:.9rem}
  .article-wrap{grid-template-columns:1fr}
  .article-side{border-left:0;border-top:1px solid var(--line);padding-left:0;padding-top:.8rem}
  .theme-dock{display:grid;grid-template-columns:1fr;gap:.4rem}
  .theme-dock select{width:100%}
  input,textarea,button,.link-button{font-size:16px;min-height:44px}
  textarea{min-height:60vh}
  .admin-editor .row-actions{position:sticky;bottom:0;background:var(--panel);padding:.5rem;border:1px solid var(--line);border-radius:10px;z-index:10}
  .back-top{bottom:4.5rem}
}
@media(max-width:480px){
  .panel{padding:.9rem;border-radius:12px}
  h1{font-size:1.3rem}
  .admin-tabs{overflow:auto;scrollbar-width:thin}
  .post-item-btn{font-size:.82rem}
}
${safeCustomCss}
    </style>
  </head>
  <body class="theme-${escapeHtml(colorTheme)}" data-default-theme="${escapeHtml(colorTheme)}">
    <main>
      ${body}
    </main>
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/contrib/auto-render.min.js"></script>
    <script>
      (function () {
        const availableThemes = ['default', 'ocean', 'forest', 'violet', 'sunset', 'mint', 'graphite'];
        const availableContrasts = ['normal', 'soft', 'strong'];
        const body = document.body;
        const dock = document.getElementById('theme-dock');
        const themeSelect = document.getElementById('theme-dock-select');
        const contrastSelect = document.getElementById('contrast-dock-select');
        const storageThemeKey = 'stublogs-theme:' + location.host;
        const storageContrastKey = 'stublogs-contrast:' + location.host;
        function safeGet(key) {
          try {
            return localStorage.getItem(key);
          } catch {
            return null;
          }
        }
        function safeSet(key, value) {
          try {
            localStorage.setItem(key, value);
          } catch {
            // ignore
          }
        }

        function applyTheme(theme, persist) {
          const nextTheme = availableThemes.includes(theme) ? theme : 'default';
          availableThemes.forEach((item) => body.classList.remove('theme-' + item));
          body.classList.add('theme-' + nextTheme);
          if (themeSelect) {
            themeSelect.value = nextTheme;
          }
          if (persist) {
            safeSet(storageThemeKey, nextTheme);
          }
          return nextTheme;
        }

        function applyContrast(level, persist) {
          const next = availableContrasts.includes(level) ? level : 'normal';
          body.classList.remove('contrast-soft', 'contrast-strong');
          if (next === 'soft') {
            body.classList.add('contrast-soft');
          } else if (next === 'strong') {
            body.classList.add('contrast-strong');
          }
          if (contrastSelect) {
            contrastSelect.value = next;
          }
          if (persist) {
            safeSet(storageContrastKey, next);
          }
          return next;
        }

        window.__applyThemeDockTheme = function(theme) {
          applyTheme(theme, true);
        };

        const defaultTheme = body.getAttribute('data-default-theme') || 'default';
        const canCustomizeTheme = Boolean(dock && themeSelect && contrastSelect);
        const storedTheme = canCustomizeTheme ? (safeGet(storageThemeKey) || defaultTheme) : defaultTheme;
        const storedContrast = canCustomizeTheme ? (safeGet(storageContrastKey) || 'normal') : 'normal';
        applyTheme(storedTheme, false);
        applyContrast(storedContrast, false);

        if (themeSelect) {
          themeSelect.addEventListener('change', () => {
            applyTheme(themeSelect.value, true);
          });
        }
        if (contrastSelect) {
          contrastSelect.addEventListener('change', () => {
            applyContrast(contrastSelect.value, true);
          });
        }

        function applyMath(retries) {
          if (typeof window.renderMathInElement !== 'function') {
            if (retries > 0) {
              setTimeout(function() {
                applyMath(retries - 1);
              }, 120);
            }
            return;
          }
          window.renderMathInElement(document.body, {
            delimiters: [
              { left: '$$', right: '$$', display: true },
              { left: '\\\\[', right: '\\\\]', display: true },
              { left: '$', right: '$', display: false },
              { left: '\\\\(', right: '\\\\)', display: false }
            ],
            ignoredTags: ['script', 'noscript', 'style', 'textarea', 'pre', 'code'],
            throwOnError: false,
            strict: 'ignore'
          });
        }

        applyMath(40);
      })();
    </script>
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

function escapeStyleTagContent(value) {
  return String(value || "")
    .replace(/\u0000/g, "")
    .replace(/<\/style/gi, "<\\/style");
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

export function renderMarkdown(source) {
  const lines = String(source || "").replace(/\r\n/g, "\n").split("\n");

  const blocks = [];
  let paragraph = [];
  let bulletItems = [];
  let orderedItems = [];
  let codeBlock = null;
  let mathBlock = null;

  const flushParagraph = () => {
    if (!paragraph.length) {
      return;
    }
    const text = paragraph.join("\n");
    blocks.push(`<p>${renderInline(text)}</p>`);
    paragraph = [];
  };

  const flushBulletList = () => {
    if (!bulletItems.length) {
      return;
    }
    blocks.push(`<ul>${bulletItems.map((item) => `<li>${renderInline(item)}</li>`).join("")}</ul>`);
    bulletItems = [];
  };

  const flushOrderedList = () => {
    if (!orderedItems.length) {
      return;
    }
    blocks.push(`<ol>${orderedItems.map((item) => `<li>${renderInline(item)}</li>`).join("")}</ol>`);
    orderedItems = [];
  };

  const flushCode = () => {
    if (!codeBlock) {
      return;
    }
    blocks.push(`<pre><code>${escapeHtml(codeBlock.join("\n"))}</code></pre>`);
    codeBlock = null;
  };

  const flushMathBlock = () => {
    if (!mathBlock) {
      return;
    }
    const formula = mathBlock.join("\n").trim();
    if (formula) {
      blocks.push(`<div class="math-block">\\[${escapeHtml(formula)}\\]</div>`);
    }
    mathBlock = null;
  };

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      flushParagraph();
      flushBulletList();
      flushOrderedList();
      flushMathBlock();

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

    if (trimmed === "$$") {
      flushParagraph();
      flushBulletList();
      flushOrderedList();

      if (mathBlock) {
        flushMathBlock();
      } else {
        mathBlock = [];
      }
      continue;
    }

    if (mathBlock) {
      mathBlock.push(line);
      continue;
    }

    if (!trimmed) {
      flushParagraph();
      flushBulletList();
      flushOrderedList();
      continue;
    }

    const singleLineMath = line.match(/^\s*\$\$(.+)\$\$\s*$/);
    if (singleLineMath) {
      flushParagraph();
      flushBulletList();
      flushOrderedList();
      blocks.push(`<div class="math-block">\\[${escapeHtml(singleLineMath[1].trim())}\\]</div>`);
      continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      flushParagraph();
      flushBulletList();
      flushOrderedList();
      const level = heading[1].length;
      blocks.push(`<h${level}>${renderInline(heading[2])}</h${level}>`);
      continue;
    }

    const listItem = line.match(/^\s*[-*]\s+(.+)$/);
    if (listItem) {
      flushParagraph();
      flushOrderedList();
      bulletItems.push(listItem[1]);
      continue;
    }

    const orderedItem = line.match(/^\s*\d+\.\s+(.+)$/);
    if (orderedItem) {
      flushParagraph();
      flushBulletList();
      orderedItems.push(orderedItem[1]);
      continue;
    }

    if (/^\s*---\s*$/.test(line)) {
      flushParagraph();
      flushBulletList();
      flushOrderedList();
      blocks.push("<hr />");
      continue;
    }

    const quote = line.match(/^>\s?(.*)$/);
    if (quote) {
      flushParagraph();
      flushBulletList();
      flushOrderedList();
      blocks.push(`<blockquote>${renderInline(quote[1])}</blockquote>`);
      continue;
    }

    paragraph.push(line);
  }

  flushParagraph();
  flushBulletList();
  flushOrderedList();
  flushCode();
  flushMathBlock();

  return blocks.join("\n");
}

function renderInline(value) {
  let text = escapeHtml(value);

  const mathTokens = [];
  const tokenPrefix = "@@MATH_TOKEN_";

  const pushMathToken = (segment) => {
    const key = `${tokenPrefix}${mathTokens.length}@@`;
    mathTokens.push(segment);
    return key;
  };

  const isEscaped = (input, index) => {
    let slashCount = 0;
    for (let cursor = index - 1; cursor >= 0 && input[cursor] === "\\"; cursor -= 1) {
      slashCount += 1;
    }
    return slashCount % 2 === 1;
  };

  // Protect math delimiters from inline markdown transforms.
  text = text.replace(/\\\[[\s\S]+?\\\]/g, (segment) => pushMathToken(segment));
  text = text.replace(/\\\([\s\S]+?\\\)/g, (segment) => pushMathToken(segment));
  text = text.replace(/\$\$[\s\S]+?\$\$/g, (segment) => pushMathToken(segment));

  let scanned = "";
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] !== "$" || isEscaped(text, index) || text[index + 1] === "$") {
      scanned += text[index];
      continue;
    }

    let end = index + 1;
    while (end < text.length) {
      if (text[end] === "$" && !isEscaped(text, end)) {
        break;
      }
      end += 1;
    }

    if (end >= text.length || end === index + 1) {
      scanned += text[index];
      continue;
    }

    scanned += pushMathToken(text.slice(index, end + 1));
    index = end;
  }
  text = scanned;

  text = text.replace(/`([^`]+)`/g, "<code>$1</code>");
  text = text.replace(/~~([^~]+)~~/g, "<del>$1</del>");
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

  for (let index = 0; index < mathTokens.length; index += 1) {
    const key = `${tokenPrefix}${index}@@`;
    text = text.split(key).join(mathTokens[index]);
  }

  text = text.replace(/\n/g, "<br />");

  return text;
}
