-- name: CreateUser :one
INSERT INTO users (display_name, name, google_id, email)
VALUES ($1, $2, $3, $4)
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



-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;


-- name: GetUserByGoogleID :one
SELECT * FROM users WHERE google_id = $1;


-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetRefreshTokenByUserId :one
SELECT refreshToken FROM users WHERE id = $1;

-- name: GetAccessTokenByUserId :one
SELECT accessToken FROM users WHERE id = $1;

-- name: InsertAccessTokenByUserId :exec
UPDATE users SET accessToken = $1 WHERE id = $2;

-- name: InsertRefreshTokenByUserId :exec
UPDATE users SET refreshToken = $1 WHERE id = $2;

-- name: InsertTokenByUserID :one
UPDATE users SET accessToken = $1, refreshToken = $2, expiry = $3, tokenType = $4 WHERE id = $5
RETURNING *;

-- name: UpdateExpiryByUserId :one
UPDATE users SET expiry = $1 WHERE id = $2
RETURNING *;

-- name: UpdateTokenTypeByUserId :one
UPDATE users SET tokenType = $1 WHERE id = $2
RETURNING *;


-- name: GetAllUsers :many
Select * from Users;