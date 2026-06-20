package tlsversion

import (
	"embed"
	"html/template"
)

//go:embed templates/*.html.tmpl
var templateFS embed.FS

// Index renders the index page. It expects data with a Version field.
var Index = template.Must(template.ParseFS(templateFS, "templates/index.html.tmpl"))

// About renders the about page.
var About = template.Must(template.ParseFS(templateFS, "templates/about.html.tmpl"))

// IndexData is the data passed to the Index template.
type IndexData struct {
	Version string
}
