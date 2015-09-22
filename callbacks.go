package authboss

import (
	"fmt"
	"reflect"
	"runtime"
)

//go:generate stringer -output stringers.go -type "Event,Interrupt"

// Event is used for callback registration.
type Event int

// Event values
const (
	EventRegister Event = iota
	EventAuth
	EventOAuth
	EventAuthFail
	EventOAuthFail
	EventRecoverStart
	EventRecoverEnd
	EventGetUser
	EventGetUserSession
	EventPasswordReset
)

// Interrupt is used to signal to callback mechanisms
// that the current process should not continue.
type Interrupt int

// Interrupt values
const (
	// InterruptNone means there was no interrupt present and the process should continue.
	InterruptNone Interrupt = iota
	// InterruptAccountLocked occurs if a user's account has been locked
	// by the lock module.
	InterruptAccountLocked
	// InterruptAccountNotConfirmed occurs if a user's account is not confirmed
	// and therefore cannot be used yet.
	InterruptAccountNotConfirmed
	// InterruptSessionExpired occurs when the user's account has had no activity for the
	// configured duration.
	InterruptSessionExpired
)

// Before callbacks can interrupt the flow by returning a bool. This is used to stop
// the callback chain and the original handler from continuing execution.
// The execution should also stopped if there is an error (and therefore if error is set
// the bool is automatically considered set).
type Before func(*Context) (Interrupt, error)

// After is a request callback that happens after the event.
type After func(*Context) error

// Callbacks is a collection of callbacks that fire before and after certain
// methods.
type Callbacks struct {
	before map[Event][]Before
	after  map[Event][]After
}

// NewCallbacks creates a new set of before and after callbacks.
// Called only by authboss internals and for testing.
func NewCallbacks() *Callbacks {
	return &Callbacks{
		make(map[Event][]Before),
		make(map[Event][]After),
	}
}

// Before event, call f.
func (c *Callbacks) Before(e Event, f Before) {
	callbacks := c.before[e]
	callbacks = append(callbacks, f)
	c.before[e] = callbacks
}

// After event, call f.
func (c *Callbacks) After(e Event, f After) {
	callbacks := c.after[e]
	callbacks = append(callbacks, f)
	c.after[e] = callbacks
}

// FireBefore event to all the callbacks with a context. The error
// should be passed up despite being logged once here already so it
// can write an error out to the HTTP Client. If err is nil then
// check the value of interrupted. If error is nil then the interrupt
// value should be checked. If it is not InterruptNone then there is a reason
// the current process should stop it's course of action.
func (c *Callbacks) FireBefore(e Event, ctx *Context) (interrupt Interrupt, err error) {
	callbacks := c.before[e]
	for _, fn := range callbacks {
		interrupt, err = fn(ctx)
		if err != nil {
			fmt.Fprintf(ctx.LogWriter, "Callback error (%s): %v\n", runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name(), err)
			return InterruptNone, err
		}
		if interrupt != InterruptNone {
			return interrupt, nil
		}
	}

	return InterruptNone, nil
}

// FireAfter event to all the callbacks with a context. The error can safely be
// ignored as it is logged.
func (c *Callbacks) FireAfter(e Event, ctx *Context) (err error) {
	callbacks := c.after[e]
	for _, fn := range callbacks {
		if err = fn(ctx); err != nil {
			fmt.Fprintf(ctx.LogWriter, "Callback error (%s): %v\n", runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name(), err)
			return err
		}
	}

	return nil
}
