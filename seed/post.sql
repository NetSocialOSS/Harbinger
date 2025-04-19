CREATE TABLE post (
    id TEXT PRIMARY KEY NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    author UUID NOT NULL REFERENCES users(id),
    isIndexed BOOLEAN NOT NULL DEFAULT TRUE,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    coterie TEXT REFERENCES coterie(name),
    scheduledfor TIMESTAMP DEFAULT NULL CHECK (scheduledfor > CURRENT_TIMESTAMP),
    image TEXT[] DEFAULT '{}'::TEXT[],
    poll JSONB DEFAULT NULL,
    hearts TEXT[] DEFAULT '{}'::TEXT[],
    comments JSONB DEFAULT NULL
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS post_author_idx ON post(author);
CREATE INDEX CONCURRENTLY IF NOT EXISTS post_coterie_idx ON post(coterie);
CREATE INDEX CONCURRENTLY IF NOT EXISTS post_createdat_idx ON post(createdAt);