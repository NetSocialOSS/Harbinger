CREATE TABLE blogpost (
    id uuid PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    slug text UNIQUE NOT NULL,
    title text NOT NULL,
    date text NOT NULL,
    authorid uuid NOT NULL REFERENCES users(id),
    overview text,
    content jsonb NOT NULL
);