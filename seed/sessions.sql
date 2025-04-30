CREATE TYPE sessions_type AS ENUM ('user-generated', 'harbinger-generated');

CREATE TABLE sessions (
    userid uuid NOT NULL REFERENCES users(id),
    token text NOT NULL UNIQUE,
    sessionid uuid NOT NULL PRIMARY KEY UNIQUE,
    device text NOT NULL,
    type sessions_type NOT NULL,
    startedat timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK (startedat <= CURRENT_TIMESTAMP),
    expiresat timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK (expiresat > CURRENT_TIMESTAMP)
);