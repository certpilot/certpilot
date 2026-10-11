package store

import "errors"

// ErrNotFound is wrapped by every lookup by id when the record does not exist,
// so a caller can tell a missing record from a failed read. The API answers 404
// for the first and 500 for the second.
var ErrNotFound = errors.New("not found")

// ErrConflict is wrapped when a write would break a uniqueness rule the caller
// is expected to handle, such as a second account made with one ACME
// credential. It is separate from a failed write so the caller can answer the
// client with the protocol's own refusal instead of a 500.
var ErrConflict = errors.New("conflict")
