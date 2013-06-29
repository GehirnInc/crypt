package common

import (
	"errors"
)

var (
	ErrSaltPrefix = errors.New("invalid magic prefix")
	ErrSaltFormat = errors.New("invalid salt format")
	ErrSaltRounds = errors.New("invalid rounds")
)
