CREATE TABLE coterie (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    name text PRIMARY KEY NOT NULL,
    description text,
    members text[] NOT NULL DEFAULT '{}'::text[],
    avatar text,
    owner uuid NOT NULL REFERENCES users(id),
    roles jsonb DEFAULT '{}'::jsonb,
    bannedmembers text[] DEFAULT '{}'::text[],
    warninglimit int DEFAULT 3,
    banner text,
    warningdetails jsonb DEFAULT '{}'::jsonb,
    isverified boolean DEFAULT FALSE,
    isorganisation boolean DEFAULT FALSE,
    ischatallowed boolean DEFAULT TRUE,
    createdat timestamp with time zone NOT NULL
);
