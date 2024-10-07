// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: logs.sql

package store

import (
	"context"
	"database/sql"

	uuid "github.com/google/uuid"
)

const getLogsByUserID = `-- name: GetLogsByUserID :many
SELECT id, user_id, api_type, created_at, comments FROM LOGS WHERE user_id = $1
`

func (q *Queries) GetLogsByUserID(ctx context.Context, userID uuid.UUID) ([]Log, error) {
	rows, err := q.db.QueryContext(ctx, getLogsByUserID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Log{}
	for rows.Next() {
		var i Log
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.ApiType,
			&i.CreatedAt,
			&i.Comments,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const insertLog = `-- name: InsertLog :exec
INSERT INTO LOGS (user_id, api_type, comments)
VALUES ($1, $2, $3)
`

type InsertLogParams struct {
	UserID   uuid.UUID
	ApiType  string
	Comments sql.NullString
}

// This is going to insert a log
func (q *Queries) InsertLog(ctx context.Context, arg InsertLogParams) error {
	_, err := q.db.ExecContext(ctx, insertLog, arg.UserID, arg.ApiType, arg.Comments)
	return err
}
