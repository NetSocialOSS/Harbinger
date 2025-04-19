CREATE TYPE notification_type AS ENUM ('like', 'comment', 'follow', 'mention');

CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    userId UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type notification_type NOT NULL,
    content TEXT,
    link TEXT,
    isRead BOOLEAN DEFAULT FALSE,
    createdAt TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS notifications_userid_idx ON notifications(userId);