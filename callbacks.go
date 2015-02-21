package authboss

import (
	"fmt"
	"reflect"
	"runtime"
)

// Event is used for callback registration.
type Event int

// These are the events that are available for use.
const (
	EventRegister Event = iota
	EventAuth
	EventAuthFail
	EventRecoverStart
	EventRecoverEnd
	EventGet
)

// Before callbacks can interrupt the flow by returning a bool. This is used to stop
// the callback chain and the original handler from continuing execution.
// The execution should also stopped if there is an error (and therefore if error is set
// the bool is automatically considered set).
type Before func(*Context) (bool, error)

// After is a request callback that happens after the event.
type After func(*Context) error

// Callbacks is a collection of callbacks that fire before and after certain
// methods.
type Callbacks struct {
	before map[Event][]Before
	after  map[Event][]After
}

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
// check the value of interrupted. If interrupted is false
// then the handler can continue it's task otherwise it must stop.
func (c *Callbacks) FireBefore(e Event, ctx *Context) (interrupted bool, err error) {
	callbacks := c.before[e]
	for _, fn := range callbacks {
		interrupted, err = fn(ctx)
		if err != nil {
			fmt.Fprintf(Cfg.LogWriter, "Callback error (%s): %v\n", runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name(), err)
			return false, err
		}
		if interrupted {
			return true, nil
		}
	}

	return false, nil
}

// FireAfter event to all the callbacks with a context. The error can safely be
// ignored as it is logged.
func (c *Callbacks) FireAfter(e Event, ctx *Context) (err error) {
	callbacks := c.after[e]
	for _, fn := range callbacks {
		if err = fn(ctx); err != nil {
			fmt.Fprintf(Cfg.LogWriter, "Callback error (%s): %v\n", runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name(), err)
			return err
		}
	}

	return nil
}
