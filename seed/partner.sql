CREATE TABLE partner (
    id uuid PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    banner text,
    logo text NOT NULL,
    title text NOT NULL,
    text text NOT NULL,
    link text NOT NULL
);