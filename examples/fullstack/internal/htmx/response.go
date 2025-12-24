package htmx

import (
	"net/http"
)

// HTMX response header names.
const (
	HXRedirect = "HX-Redirect"
	HXRefresh  = "HX-Refresh"
	HXTrigger  = "HX-Trigger"
	HXReswap   = "HX-Reswap"
	HXRetarget = "HX-Retarget"
	HXRequest  = "HX-Request"
)

// IsHTMXRequest checks if the request is an HTMX request.
func IsHTMXRequest(r *http.Request) bool {
	return r.Header.Get(HXRequest) == "true"
}

// Redirect sends an HTMX redirect header.
func Redirect(w http.ResponseWriter, url string) {
	w.Header().Set(HXRedirect, url)
}

// Refresh triggers a full page refresh.
func Refresh(w http.ResponseWriter) {
	w.Header().Set(HXRefresh, "true")
}

// Trigger sends an HTMX trigger event.
func Trigger(w http.ResponseWriter, event string) {
	w.Header().Set(HXTrigger, event)
}

// Reswap changes the swap behavior.
func Reswap(w http.ResponseWriter, swap string) {
	w.Header().Set(HXReswap, swap)
}

// Retarget changes the target element.
func Retarget(w http.ResponseWriter, target string) {
	w.Header().Set(HXRetarget, target)
}
