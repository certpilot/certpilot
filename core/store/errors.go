package store

import "errors"

// ErrNotFound is wrapped by every lookup by id when the record does not exist,
// so a caller can tell a missing record from a failed read. The API answers 404
// for the first and 500 for the second.
var ErrNotFound = errors.New("not found")
