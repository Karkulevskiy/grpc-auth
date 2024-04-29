package storage

import "errors"

var (
	ErrUserAlreadyExists = errors.New("ErrUserAlreadyExists")
	ErrUserNotFound      = errors.New("ErrUserNotFound")
	ErrAppNotFound       = errors.New("ErrAppNotFound")
)
