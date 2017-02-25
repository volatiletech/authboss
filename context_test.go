package authboss

/* TODO(aarondl): Re-enable

func TestCurrentUserID(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.SessionStoreMaker = newMockClientStoreMaker(mockClientStore{
		SessionKey: "george-pid",
	})

	id, err := ab.CurrentUserID(nil, httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Error(err)
	}

	if id != "george-pid" {
		t.Error("got:", id)
	}
}

func TestCurrentUserIDContext(t *testing.T) {
	t.Parallel()

	ab := New()
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyPID, "george-pid"))
	id, err := ab.CurrentUserID(nil, req)
	if err != nil {
		t.Error(err)
	}

	if id != "george-pid" {
		t.Error("got:", id)
	}
}

func TestCurrentUserIDP(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.SessionStoreMaker = newMockClientStoreMaker(mockClientStore{})

	defer func() {
		if recover().(error) != ErrUserNotFound {
			t.Failed()
		}
	}()

	_ = ab.CurrentUserIDP(nil, httptest.NewRequest("GET", "/", nil))
}

func TestCurrentUser(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.SessionStoreMaker = newMockClientStoreMaker(mockClientStore{
		SessionKey: "george-pid",
	})
	ab.StoreLoader = mockStoreLoader{
		"george-pid": mockUser{Email: "george-pid", Password: "unreadable"},
	}

	user, err := ab.CurrentUser(nil, httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Error(err)
	}

	if got, err := user.GetEmail(context.TODO()); err != nil {
		t.Error(err)
	} else if got != "george-pid" {
		t.Error("got:", got)
	}
}

func TestCurrentUserContext(t *testing.T) {
	t.Parallel()

	ab := New()
	wantUser := mockStoredUser{
		mockUser: mockUser{Email: "george-pid", Password: "unreadable"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), ctxKeyPID, "george-id")
	ctx = context.WithValue(ctx, ctxKeyUser, wantUser)
	req = req.WithContext(ctx)

	user, err := ab.CurrentUser(nil, req)
	if err != nil {
		t.Error(err)
	}

	if got, err := user.GetEmail(context.TODO()); err != nil {
		t.Error(err)
	} else if got != "george-pid" {
		t.Error("got:", got)
	}
}

func TestCurrentUserP(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.SessionStoreMaker = newMockClientStoreMaker(mockClientStore{
		SessionKey: "george-pid",
	})
	ab.StoreLoader = mockStoreLoader{}

	defer func() {
		if recover().(error) != ErrUserNotFound {
			t.Failed()
		}
	}()

	_ = ab.CurrentUserP(nil, httptest.NewRequest("GET", "/", nil))
}

func TestLoadCurrentUserID(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.SessionStoreMaker = newMockClientStoreMaker(mockClientStore{
		SessionKey: "george-pid",
	})

	req := httptest.NewRequest("GET", "/", nil)

	id, err := ab.LoadCurrentUserID(nil, &req)
	if err != nil {
		t.Error(err)
	}

	if id != "george-pid" {
		t.Error("got:", id)
	}

	if req.Context().Value(ctxKeyPID).(string) != "george-pid" {
		t.Error("context was not updated in local request")
	}
}

func TestLoadCurrentUserIDP(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.SessionStoreMaker = newMockClientStoreMaker(mockClientStore{})

	defer func() {
		if recover().(error) != ErrUserNotFound {
			t.Failed()
		}
	}()

	req := httptest.NewRequest("GET", "/", nil)
	_ = ab.LoadCurrentUserIDP(nil, &req)
}

func TestLoadCurrentUser(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.SessionStoreMaker = newMockClientStoreMaker(mockClientStore{
		SessionKey: "george-pid",
	})
	ab.StoreLoader = mockStoreLoader{
		"george-pid": mockUser{Email: "george-pid", Password: "unreadable"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	user, err := ab.LoadCurrentUser(nil, &req)
	if err != nil {
		t.Error(err)
	}

	if got, err := user.GetEmail(context.TODO()); err != nil {
		t.Error(err)
	} else if got != "george-pid" {
		t.Error("got:", got)
	}

	want := user.(mockStoredUser).mockUser
	got := req.Context().Value(ctxKeyUser).(mockStoredUser).mockUser
	if got != want {
		t.Error("users mismatched:\nwant: %#v\ngot: %#v", want, got)
	}
}

func TestLoadCurrentUserContext(t *testing.T) {
	t.Parallel()

	ab := New()
	wantUser := mockStoredUser{
		mockUser: mockUser{Email: "george-pid", Password: "unreadable"},
	}

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), ctxKeyPID, "george-id")
	ctx = context.WithValue(ctx, ctxKeyUser, wantUser)
	req = req.WithContext(ctx)

	user, err := ab.LoadCurrentUser(nil, &req)
	if err != nil {
		t.Error(err)
	}

	got := user.(mockStoredUser).mockUser
	if got != wantUser.mockUser {
		t.Error("users mismatched:\nwant: %#v\ngot: %#v", wantUser.mockUser, got)
	}
}

func TestLoadCurrentUserP(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.SessionStoreMaker = newMockClientStoreMaker(mockClientStore{
		SessionKey: "george-pid",
	})
	ab.StoreLoader = mockStoreLoader{}

	defer func() {
		if recover().(error) != ErrUserNotFound {
			t.Failed()
		}
	}()

	req := httptest.NewRequest("GET", "/", nil)
	_ = ab.LoadCurrentUserP(nil, &req)
}
*/
