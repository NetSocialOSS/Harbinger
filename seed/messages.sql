CREATE TYPE messages_type AS ENUM ('message', 'media-only', 'mms');

CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    coterie TEXT NOT NULL,
    userid UUID NOT NULL references users(id),
    content TEXT NOT NULL,
    type messages_type NOT NULL,
    createdat TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);