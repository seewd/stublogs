PRAGMA foreign_keys = ON;

ALTER TABLE posts
ADD COLUMN is_page INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_posts_site_ispage_published_updated
ON posts(site_id, is_page, published, updated_at DESC);
