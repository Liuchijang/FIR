package module

const (
	StatusSuccess   = "success"
	StatusFailed    = "failed"
	StatusSkipped   = "skipped"
	StatusCancelled = "cancelled"
	StatusTimeout   = "timeout"

	ErrorKindCancelled = "cancelled"
	ErrorKindTimeout   = "timeout"
	ErrorKindPanic     = "panic"
	ErrorKindModule    = "module_error"
)
