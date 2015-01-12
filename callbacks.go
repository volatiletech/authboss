package authboss

// Event is used for callback registration.
type Event int

// These are the events that are available for use.
const (
	EventRegister Event = iota
	EventAuth
)

// Before callbacks can interrupt the flow by returning an error. This is used to stop
// the callback chain and the original handler from executing.
type Before func(*Context) error

// After is a request callback that happens after the event.
type After func(*Context)

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

// Before event, call callback.
func (c *Callbacks) Before(e Event, f Before) {
	callbacks := c.before[e]
	callbacks = append(callbacks, f)
	c.before[e] = callbacks
}

// After event, call callback.
func (c *Callbacks) After(e Event, f After) {
	callbacks := c.after[e]
	callbacks = append(callbacks, f)
	c.after[e] = callbacks
}

// FireBefore event to all the callbacks with a context.
func (c *Callbacks) FireBefore(e Event, ctx *Context) error {
	callbacks := c.before[e]
	for _, fn := range callbacks {
		err := fn(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

// FireAfter event to all the callbacks with a context.
func (c *Callbacks) FireAfter(e Event, ctx *Context) {
	callbacks := c.after[e]
	for _, fn := range callbacks {
		fn(ctx)
	}
}
