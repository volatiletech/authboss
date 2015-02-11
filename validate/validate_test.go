package validate

import (
	"bytes"
	"net/http"
	"testing"

	"gopkg.in/authboss.v0"
)

func TestValidate_Initialiaze(t *testing.T) {
	cfg := authboss.NewConfig()
	cfg.Policies = []authboss.Validator{
		authboss.Rules{FieldName: policyEmail},
		authboss.Rules{FieldName: policyUsername},
		authboss.Rules{FieldName: policyPassword},
	}

	err := V.Initialize(cfg)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if V.Email == nil {
		t.Error("Should have set Email validator.")
	}
	if V.Username == nil {
		t.Error("Should have set Username validator.")
	}
	if V.Password == nil {
		t.Error("Should have set Password validator.")
	}
}

func TestValidate_BeforeRegister(t *testing.T) {
	cfg := authboss.NewConfig()
	cfg.Policies = []authboss.Validator{
		authboss.Rules{FieldName: policyEmail, MinLength: 15},
		authboss.Rules{FieldName: policyUsername, MaxLength: 1},
		authboss.Rules{FieldName: policyPassword, MinLength: 8},
	}

	err := V.Initialize(cfg)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	body := `email=joe@joe.ca&password=hi&username=hello`
	req, err := http.NewRequest("POST", "http://localhost", bytes.NewBufferString(body))
	if err != nil {
		t.Error("Unexpected Error:", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx, err := authboss.ContextFromRequest(req)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	err = V.BeforeRegister(ctx)
	if err == nil {
		t.Error("Expected three validation errors.")
	}

	list := err.(authboss.ErrorList)
	if len(list) != 3 {
		t.Error("Expected three validation errors.")
	}
}
