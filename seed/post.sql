CREATE TABLE post (
    id text PRIMARY KEY NOT NULL,
    title text NOT NULL,
    content text NOT NULL,
    author uuid NOT NULL REFERENCES users(id),
    isindexed boolean NOT NULL DEFAULT TRUE,
    createdat timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    coterie text REFERENCES coterie(name),
    scheduledfor timestamp DEFAULT NULL CHECK (scheduledfor > CURRENT_TIMESTAMP),
    image text[] DEFAULT '{}'::text[],
    poll jsonb DEFAULT NULL,
    hearts text[] DEFAULT '{}'::text[],
    comments jsonb DEFAULT NULL
);