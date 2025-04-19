CREATE TABLE blogpost (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    slug TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL, 
    date TEXT NOT NULL,
    authorId UUID NOT NULL REFERENCES users(id),
    overview TEXT,
    content JSONB NOT NULL
);