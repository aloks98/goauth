package handlers

import (
	"context"
	"net/http"

	"github.com/aloks98/goauth/examples/fullstack/internal/app"
)

// Context is a framework-agnostic request context interface.
// Each framework (gin, chi, echo, fiber) implements this interface.
type Context interface {
	// Request context
	Context() context.Context
	Request() *http.Request
	ResponseWriter() http.ResponseWriter

	// User info (from middleware)
	UserID() string
	Claims() interface{}

	// Request data
	FormValue(key string) string
	Param(key string) string

	// Response methods
	SetCookie(cookie *http.Cookie)
	Redirect(url string, code int) error
	Render(name string, data interface{}) error
	RenderPartial(name string, data interface{}) error
	JSON(code int, data interface{}) error
	String(code int, s string) error
	NoContent(code int) error

	// HTMX helpers
	IsHTMX() bool
	HXRedirect(url string)
	HXTrigger(event string)
}

// Handler holds all HTTP handlers for the application.
type Handler struct {
	app *app.App
}

// New creates a new Handler.
func New(app *app.App) *Handler {
	return &Handler{app: app}
}

// Flash represents a flash message.
type Flash struct {
	Type    string // success, danger, warning
	Message string
}

// UserData represents user information for templates.
type UserData struct {
	ID          string
	Email       string
	Name        string
	Role        string
	Permissions []string
}

// PageData is the base data passed to all templates.
type PageData struct {
	Title  string
	Active string // Active nav item
	User   *UserData
	Flash  *Flash
}
