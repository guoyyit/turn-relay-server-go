package turn

// TURN/STUN error codes (RFC 5389 / RFC 5766).
const (
	CodeBadRequest           = 400
	CodeUnauthorized         = 401
	CodeForbidden            = 403
	CodeAllocMismatch        = 437
	CodeWrongCredentials     = 441
	CodeUnsupportedTransport = 442
	CodeAllocQuotaReached    = 486
	CodeStaleNonce           = 438
	CodeInsufficientCapacity = 508
)

// turnError carries a STUN error code and reason phrase.
type turnError struct {
	code   int
	reason string
}

func (e *turnError) Error() string { return e.reason }

func newTurnError(code int, reason string) *turnError {
	return &turnError{code: code, reason: reason}
}
