package authboss

import "testing"

func TestCasingStyleConversions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		In  string
		Out string
	}{
		{"SomethingInCamel", "something_in_camel"},
		{"Oauth2Anything", "oauth2_anything"},
	}

	for i, test := range tests {
		out := camelToUnder(test.In)
		if out != test.Out {
			t.Errorf("%d) Expected %q got %q", i, test.Out, out)
		}
		out = underToCamel(out)
		if out != test.In {
			t.Errorf("%d), Expected %q got %q", i, test.In, out)
		}
	}
}
