-- name: IsMessageProcessed :one
SELECT EXISTS (SELECT 1 FROM processed_emails WHERE message_id = $1);

-- name: MarkMessageAsProcessed :exec
INSERT INTO processed_emails (message_id) VALUES ($1)
ON CONFLICT (message_id) DO NOTHING
RETURNING message_id;
