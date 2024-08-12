-- name: CreateUser :one
INSERT INTO users (id, display_name, name, credentials, google_id, email)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetUserByName :one
SELECT * FROM users
WHERE name = $1 LIMIT 1;

-- name: InsertIntoSessions :one
INSERT INTO sessions (id, user_id, data, expires)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetSession :one
SELECT * FROM sessions
WHERE id = $1 LIMIT 1;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = $1;


-- name: GetUserByUsername :one
SELECT * FROM users
WHERE name = $1 LIMIT 1;

-- name: GetUserById :one
SELECT * FROM users
WHERE id = $1 LIMIT 1;


-- name: UpdateUser :one
UPDATE users
SET display_name = $2,
    name = $3,
    credentials = $4
WHERE id = $1
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;


-- name: GetUserByGoogleID :one
SELECT * FROM users WHERE google_id = $1;


-- name: GetUserByProdApiKey :one
SELECT * FROM users WHERE api_key = $1;

-- name: GetUserByDevApiKey :one
SELECT * FROM users WHERE api_key_dev = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: CheckIfValidKey :one
SELECT * FROM users WHERE api_key = $1 OR api_key_dev = $1;