// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package store

import (
	"database/sql"
	"time"

	uuid "github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
)

type Log struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ApiType   string
	CreatedAt sql.NullTime
	Comments  sql.NullString
}

type ProcessedEmail struct {
	MessageID   string
	ProcessedAt sql.NullTime
}

type Session struct {
	ID      string
	UserID  string
	Data    pqtype.NullRawMessage
	Expires time.Time
}

type User struct {
	ID           uuid.UUID
	Email        string
	Name         string
	DisplayName  string
	GoogleID     sql.NullString
	CreatedAt    sql.NullTime
	UpdatedAt    sql.NullTime
	ApiKey       sql.NullString
	ApiKeyDev    sql.NullString
	Refreshtoken sql.NullString
	Accesstoken  sql.NullString
	Expiry       sql.NullTime
	Tokentype    sql.NullString
	Persona      sql.NullString
	MicrosoftID  sql.NullString
}
