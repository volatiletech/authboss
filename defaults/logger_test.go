package defaults

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestLogger(t *testing.T) {
	t.Parallel()

	b := &bytes.Buffer{}
	logger := NewLogger(b)

	logger.Info("hello")
	logger.Error("world")

	rgxTimestamp := `[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z`
	rgx := regexp.MustCompile(rgxTimestamp + ` \[INFO\]: hello\n` + rgxTimestamp + ` \[EROR\]: world\n`)
	if !rgx.Match(b.Bytes()) {
		t.Errorf("output from log file did not match regex:\n%s\n%v", b.String(), b.Bytes())
		spew.Dump(b.Bytes())
	}
}
