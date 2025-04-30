CREATE TYPE notification_type AS ENUM ('like', 'comment', 'follow', 'mention');

CREATE TABLE notifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    userid uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type notification_type NOT NULL,
    content text,
    link text,
    isread boolean DEFAULT FALSE,
    createdat timestamptz DEFAULT CURRENT_TIMESTAMP
);