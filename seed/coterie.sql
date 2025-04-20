CREATE TABLE coterie (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    name TEXT PRIMARY KEY NOT NULL,
    description TEXT,
    members TEXT[] NOT NULL DEFAULT '{}'::TEXT[],
    avatar TEXT,
    owner UUID NOT NULL REFERENCES users(id),
    roles JSONB DEFAULT '{}'::JSONB,
    bannedmembers TEXT[] DEFAULT '{}'::TEXT[],
    warninglimit INT DEFAULT 3,
    banner TEXT,
    warningdetails JSONB DEFAULT '{}'::JSONB,
    isverified BOOLEAN DEFAULT FALSE,
    isorganisation BOOLEAN DEFAULT FALSE,
    ischatallowed BOOLEAN DEFAULT TRUE,
    createdat TIMESTAMP WITH TIME ZONE NOT NULL
);