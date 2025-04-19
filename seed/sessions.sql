CREATE TYPE sessions_type AS ENUM ('user-generated', 'harbinger-generated');

CREATE TABLE sessions (
    userId UUID NOT NULL references users(id),
    token TEXT NOT NULL UNIQUE,
    sessionid UUID NOT NULL PRIMARY KEY UNIQUE,
    device TEXT NOT NULL,
    type sessions_type NOT NULL,
    startedat TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK (startedat <= CURRENT_TIMESTAMP),
    expiresat TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK (expiresat > CURRENT_TIMESTAMP)                                         
);