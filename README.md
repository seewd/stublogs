# Stublogs（Cloudflare + GitHub）

`Stublogs` 是一個參考 Bearblog 思路的極簡多租戶 Blog 平台：

- 入口主頁：`https://blog.bdfz.net`（Cloudflare Pages）
- 學生站點：`https://xxx.bdfz.net`
- 文章網址：`https://xxx.bdfz.net/hello-world`
- 編輯後台：`https://xxx.bdfz.net/admin`
- 內容儲存：GitHub Repo（Markdown）
- 站點映射/文章 metadata：Cloudflare D1

## 架構總覽

1. **Cloudflare Pages（主頁）**
- 網域：`blog.bdfz.net`
- 原始碼目錄：`pages/`
- 功能：註冊表單、使用說明（正體中文）

2. **Cloudflare Worker（多租戶後端）**
- 路由：`*.bdfz.net/*`
- 解析 `Host` 的第一段作為 `slug`
- 依 `slug -> site_id` 查 D1 並渲染站點

3. **DNS（Wildcard）**
- Zone：`bdfz.net`
- 必要記錄：`* CNAME app.bdfz.net`（Proxied）
- `app.bdfz.net` 需有可被代理的入口記錄

## 已實作功能

- `GET /api/check-slug`：即時檢查 slug
- `POST /api/register`：註冊站點（**需邀請碼**）
- `POST /api/login` / `POST /api/logout`
- `GET /api/list-posts`
- `GET /api/posts/:postSlug`
- `POST /api/posts`
- `GET /api/export`（站點資料匯出 JSON）
- 極簡 Bear 風格後台：`/admin`

## 註冊限制

### slug 規則

- 全小寫
- 僅允許 `a-z 0-9 -`
- 長度 `2~30`
- 不可 `-` 開頭/結尾
- 不可包含 `--`
- 保留詞不可註冊

### 邀請碼

`POST /api/register` 必須帶 `inviteCode`，Worker 會驗證環境變數 `INVITE_CODES`。

## 環境變數

### Worker vars / secrets

- `BASE_DOMAIN=bdfz.net`
- `RESERVED_SLUGS=...`
- `CORS_ALLOWED_ORIGINS=https://blog.bdfz.net`
- `SESSION_SECRET`（secret）
- `GITHUB_OWNER`（secret）
- `GITHUB_REPO`（secret）
- `GITHUB_TOKEN`（secret）
- `GITHUB_BRANCH=main`
- `INVITE_CODES=code1,code2`（建議設為 secret）

本地參考：`.dev.vars.example`

## 目前保留詞（已核查現有子域名）

已於 **2026-02-21** 依 Cloudflare DNS 現況更新：

`750,admin,ai,api,api-mark,app,assets,blog,bwh2,cdn,chat,class,d,dashboard,dl,dmit,dmit160,dmit197,dmit2t,dmitpro2,dms,docs,ff,files,forum,ftp,gcjp,gcsg,gcus,gk,h,hlm,i,img,jc,jks,jks-ai,jpg,kama,kb,kw,kz,mail,mark,me,media,mf,moxie,mx,o,paper,ra112,ra154,rfc,seiue,ssh,static,status,stu,t,todo,tree,upvote,vpn,www,wx,xz`

> 清單寫在 `wrangler.toml` 的 `RESERVED_SLUGS`。

## 本地開發

1. 安裝依賴

```bash
npm install
```

2. 建立 D1 並填回 `wrangler.toml` 的 `database_id`

```bash
npx wrangler d1 create stublogs-db
```

3. 套 migration

```bash
npx wrangler d1 migrations apply stublogs-db --local
```

4. 設定本地環境變數

```bash
cp .dev.vars.example .dev.vars
```

5. 啟動 Worker

```bash
npm run dev
```

## 部署步驟

### 1) Worker

```bash
npx wrangler secret put SESSION_SECRET
npx wrangler secret put GITHUB_OWNER
npx wrangler secret put GITHUB_REPO
npx wrangler secret put GITHUB_TOKEN
npx wrangler secret put INVITE_CODES
npx wrangler d1 migrations apply stublogs-db --remote
npm run deploy
```

### 2) Pages（`blog.bdfz.net`）

```bash
npx wrangler pages project create stublogs-home --production-branch main
npx wrangler pages deploy pages --project-name stublogs-home
npx wrangler pages domain add blog.bdfz.net --project-name stublogs-home
```

## 專案檔案

- `src/index.js`：Worker 主程式
- `migrations/0001_init.sql`：D1 schema
- `pages/index.html`：主頁（正體中文）
- `pages/app.js`：註冊流程（呼叫 `https://app.bdfz.net/api/*`）
- `pages/styles.css`：主頁樣式
- `wrangler.toml`：Worker 設定
- `tests/slug.test.js`：slug 規則測試
