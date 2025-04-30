CREATE TABLE partner (
    id uuid PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    banner text,
    logo text NOT NULL,
    createdat timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    title text NOT NULL,
    text text NOT NULL,
    link text NOT NULL
);