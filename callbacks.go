package authboss

// Before callbacks can interrupt the flow by returning an error. This is used to stop
// the callback chain and the original handler from executing.
type Before func(Context) error

// After is a request callback that happens after the event.
type After func(Context)

// Callbacks is a collection of callbacks that fire before and after certain
// methods.
type Callbacks struct {
	beforeAuth []Before
	afterAuth  []After
}

func NewCallbacks() *Callbacks {
	return &Callbacks{
		make([]Before, 0),
		make([]After, 0),
	}
}

func (c *Callbacks) AddBeforeAuth(f Before) {
	c.beforeAuth = append(c.beforeAuth, f)
}

func (c *Callbacks) AddAfterAuth(f After) {
	c.afterAuth = append(c.afterAuth, f)
}

func (c *Callbacks) BeforeAuth(ctx Context) error {
	for _, fn := range c.beforeAuth {
		err := fn(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Callbacks) AfterAuth(ctx Context) {
	for _, fn := range c.afterAuth {
		fn(ctx)
	}
}
