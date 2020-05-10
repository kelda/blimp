package errors

import (
	"fmt"
	"os"

	"github.com/buger/goterm"
)

// ContextError is an error that has information on what caused it.
type ContextError interface {
	Cause() error
	Context() string

	Error() string
}

// A FriendlyError is an error with that can be directly printed to the user
// without any other context.
type FriendlyError interface {
	FriendlyMessage() string
	Error() string
}

type contextErrorImpl struct {
	err     error
	context string
}

func (err contextErrorImpl) Context() string {
	return err.context
}

func (err contextErrorImpl) Error() string {
	// If we one of our children is a friendly error, print that.
	if friendlyMsg, ok := getFriendlyMessage(err); ok {
		return friendlyMsg
	}

	// Otherwise, print the full error tree.
	return fmt.Sprintf("%s: %s", err.context, err.err)
}

func (err contextErrorImpl) Cause() error {
	return err.err
}

type friendlyErrorImpl struct {
	message string
}

func (err friendlyErrorImpl) Error() string {
	return err.message
}

func (err friendlyErrorImpl) FriendlyMessage() string {
	return err.message
}

// WithContext returns an error that can be unwrapped by `Cause`.
func WithContext(context string, err error) error {
	return contextErrorImpl{err, context}
}

// Cause returns the cause of the given error if it's defined.
func Cause(err error) (error, bool) { // nolint: golint, staticcheck, stylecheck
	errWithContext, ok := err.(ContextError)
	if !ok {
		return nil, false
	}
	return errWithContext.Cause(), true
}

// RootCause returns the root cause of the given error.
func RootCause(err error) error {
	for {
		cause, ok := Cause(err)
		if !ok {
			return err
		}
		err = cause
	}
}

// New returns a new Go error. It is provided so that callers don't have to
// import both the Go "errors" package and this package.
func New(f string, args ...interface{}) error {
	return fmt.Errorf(f, args...)
}

// NewFriendlyError returns a new user friendly error that can be retrieved by
// GetPrintableMessage.
func NewFriendlyError(f string, args ...interface{}) error {
	return friendlyErrorImpl{fmt.Sprintf(f, args...)}
}

// GetPrintableMessage returns a user friendly error to print to the user.
// If any error in the error chain has a user friendly error message, it prints
// that. Otherwise, it prints the errors' generic message.
func GetPrintableMessage(err error) string {
	if friendlyMsg, ok := getFriendlyMessage(err); ok {
		return friendlyMsg
	}
	return err.Error()
}

func getFriendlyMessage(err error) (string, bool) {
	friendlyError, ok := err.(FriendlyError)
	if ok {
		return friendlyError.FriendlyMessage(), true
	}

	cause, ok := Cause(err)
	if !ok {
		return "", false
	}
	return getFriendlyMessage(cause)
}

func HandleFatalError(err error) {
	fmt.Fprintln(os.Stderr,
		goterm.Color("FATAL ERROR: Get help at https://kelda.io/blimp/docs/help/", goterm.RED))
	fmt.Fprintln(os.Stderr, GetPrintableMessage(err))
	os.Exit(1)
}
