package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/karkulevskiy/sso/internal/domain/models"
	"github.com/karkulevskiy/sso/internal/storage"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

type Storage struct {
	db *sql.DB
}

func New(connectionString string) (*Storage, error) {
	const op = "storage.Postgres.New"

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.Postgres.SaveUser"

	stmt, err := s.db.Prepare("INSERT INTO users_grpc (email, pass_hash) VALUES ($1, $2) RETURNING id")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	rows, err := stmt.QueryContext(ctx, email, passHash)
	if err != nil {
		if postgresErr, ok := err.(*pq.Error); ok && postgresErr.Constraint != "" {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserAlreadyExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	defer rows.Close()

	var userID int64

	for rows.Next() {
		if err := rows.Scan(&userID); err != nil {
			return 0, fmt.Errorf("%s: %w", op, err)
		}
	}

	if rows.Err() != nil {
		return 0, fmt.Errorf("%s: %w", op, rows.Err())
	}

	return userID, nil
}

func (s *Storage) User(ctx context.Context, email string) (*models.User, error) {
	const op = "storage.Postgres.User"

	stmt, err := s.db.Prepare("SELECT (id, email, pass_hash) FROM users_grpc WHERE email = $1")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	var user models.User

	err = row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &models.User{
		ID:       user.ID,
		Email:    user.Email,
		PassHash: user.PassHash,
	}, nil
}

// TODO: Разобраться в чем разница в Prepare, PrepareContext, QueryContext
func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.Postgres.IsAdmin"

	stmt, err := s.db.Prepare("SELECT is_admin FROM users_grpc WHERE id = $1")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, userID)

	var isAdmin bool

	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}
