PRAGMA foreign_keys = ON;

ALTER TABLE posts
ADD COLUMN exclude_from_campus_feed INTEGER NOT NULL DEFAULT 0;

UPDATE posts
SET exclude_from_campus_feed = 1
WHERE post_slug = 'hello-world' AND title = 'Hello World';

CREATE INDEX IF NOT EXISTS idx_posts_published_campus_updated
ON posts(published, exclude_from_campus_feed, updated_at DESC);
