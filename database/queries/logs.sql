-- This is going to insert a log
-- name: InsertLog :exec
INSERT INTO LOGS (user_id, api_type, comments)
VALUES ($1, $2, $3);

-- name: GetLogsByUserID :many
SELECT * FROM LOGS WHERE user_id = $1;

