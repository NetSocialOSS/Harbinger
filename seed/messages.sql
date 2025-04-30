CREATE TYPE messages_type AS ENUM ('message', 'media-only', 'mms');

CREATE TABLE messages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    coterie text NOT NULL,
    userid uuid NOT NULL REFERENCES users(id),
    content text NOT NULL,
    type messages_type NOT NULL,
    createdat timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);