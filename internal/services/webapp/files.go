package webapp

import (
	"fmt"
	"net/http"
	"path/filepath"
)

func serveFile(w http.ResponseWriter, r *http.Request, path string, downloadBase string) {
	name := filepath.Base(path)
	if downloadBase != "" {
		ext := filepath.Ext(name)
		name = downloadBase + ext
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	http.ServeFile(w, r, path)
}
