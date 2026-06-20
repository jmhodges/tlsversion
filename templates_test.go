package tlsversion

import (
	"strings"
	"testing"
)

func TestIndexRender(t *testing.T) {
	var buf strings.Builder
	if err := Index.Execute(&buf, IndexData{Version: "TLS 1.3"}); err != nil {
		t.Fatalf("rendering index: %s", err)
	}
	out := buf.String()

	for _, want := range []string{
		"<!DOCTYPE html>",
		"TLS 1.3", // version content from the page block
		`<title>TLS 1.3 — tlsversion.com</title>`, // title block override
		`href="/about"`, // link to the about page
	} {
		if !strings.Contains(out, want) {
			t.Errorf("index output missing %q\n---\n%s", want, out)
		}
	}
}

func TestAboutRender(t *testing.T) {
	var buf strings.Builder
	if err := About.Execute(&buf, nil); err != nil {
		t.Fatalf("rendering about: %s", err)
	}
	out := buf.String()

	for _, want := range []string{
		"<!DOCTYPE html>",
		`<title>About — tlsversion.com</title>`,
		"<h1>About</h1>",
		`href="/"`, // link back home
	} {
		if !strings.Contains(out, want) {
			t.Errorf("about output missing %q\n---\n%s", want, out)
		}
	}
}
