package internal

// InitializationError distinguishes unavailable probe resources from send errors.
// The scheduler must terminate instead of converting it into a timeout.
type InitializationError struct{ Err error }

func (e *InitializationError) Error() string { return e.Err.Error() }
func (e *InitializationError) Unwrap() error { return e.Err }
