package authboss

import "context"

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

// Before Events can interrupt the flow by returning an interrupt value.
// This is used to stop the callback chain and the original handler from
// continuing execution. The execution should also stopped if there is an error.
type Before func(context.Context) (Interrupt, error)

// After is a request callback that happens after the event.
type After func(context.Context) error

// Events is a collection of Events that fire before and after certain
// methods.
type Events struct {
	before map[Event][]Before
	after  map[Event][]After
}

// NewEvents creates a new set of before and after Events.
// Called only by authboss internals and for testing.
func NewEvents() *Events {
	return &Events{
		before: make(map[Event][]Before),
		after:  make(map[Event][]After),
	}
}

// Before event, call f.
func (c *Events) Before(e Event, f Before) {
	Events := c.before[e]
	Events = append(Events, f)
	c.before[e] = Events
}

// After event, call f.
func (c *Events) After(e Event, f After) {
	Events := c.after[e]
	Events = append(Events, f)
	c.after[e] = Events
}

// FireBefore event to all the Events with a context. The error
// should be passed up despite being logged once here already so it
// can write an error out to the HTTP Client. If err is nil then
// check the value of interrupted. If error is nil then the interrupt
// value should be checked. If it is not InterruptNone then there is a reason
// the current process should stop it's course of action.
func (c *Events) FireBefore(ctx context.Context, e Event) (interrupt Interrupt, err error) {
	Events := c.before[e]
	for _, fn := range Events {
		interrupt, err = fn(ctx)
		if err != nil {
			return InterruptNone, err
		}
		if interrupt != InterruptNone {
			return interrupt, nil
		}
	}

	return InterruptNone, nil
}

// FireAfter event to all the Events with a context. The error can safely be
// ignored as it is logged.
func (c *Events) FireAfter(ctx context.Context, e Event) (err error) {
	Events := c.after[e]
	for _, fn := range Events {
		if err = fn(ctx); err != nil {
			return err
		}
	}

	return nil
}
