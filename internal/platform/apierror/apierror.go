// Package apierror defines the single JSON error format of the API and the
// central error handler that produces it.
package apierror

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"
)

// Machine-readable error codes. Clients switch on the code, never on the message.
const (
	CodeInvalidRequest       = "invalid_request"
	CodeInvalidCredentials   = "invalid_credentials"
	CodeUnauthenticated      = "unauthenticated"
	CodeForbidden            = "forbidden"
	CodeNotFound             = "not_found"
	CodeMethodNotAllowed     = "method_not_allowed"
	CodeRequestTooLarge      = "request_too_large"
	CodeUnsupportedMediaType = "unsupported_media_type"
	CodeTooManyRequests      = "too_many_requests"
	CodeHTTPSRequired        = "https_required"
	CodeInternal             = "internal_error"
)

// Body is the JSON envelope of every error response.
type Body struct {
	Error Detail `json:"error"`
}

// Detail is the content of the error envelope.
type Detail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Write sends the error envelope with the given status.
func Write(c *echo.Context, status int, code, message string) error {
	return c.JSON(status, Body{Error: Detail{Code: code, Message: message}})
}

// Handler is the echo.HTTPErrorHandler of the API. Every error, including the
// router's 404 and 405, leaves the server in the same envelope. Server errors
// are logged with their details and answered with a generic message: internals
// never reach the client.
func Handler(c *echo.Context, err error) {
	if resp, _ := echo.UnwrapResponse(c.Response()); resp != nil && resp.Committed {
		return
	}

	status := echo.StatusCode(err)
	if status == 0 {
		status = http.StatusInternalServerError
	}

	message := http.StatusText(status)
	if status >= http.StatusInternalServerError {
		c.Logger().Error("request failed",
			"method", c.Request().Method, "path", c.Request().URL.Path, "error", err)
		message = "internal server error"
	} else if he := (*echo.HTTPError)(nil); errors.As(err, &he) && he.Message != "" {
		message = he.Message // a specific, safe explanation for the client
	}

	if c.Request().Method == http.MethodHead {
		_ = c.NoContent(status)
		return
	}
	if werr := Write(c, status, codeForStatus(status), message); werr != nil {
		c.Logger().Error("cannot send error response", "error", werr)
	}
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeInvalidRequest
	case http.StatusUnauthorized:
		return CodeUnauthenticated
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusMethodNotAllowed:
		return CodeMethodNotAllowed
	case http.StatusRequestEntityTooLarge:
		return CodeRequestTooLarge
	case http.StatusUnsupportedMediaType:
		return CodeUnsupportedMediaType
	case http.StatusTooManyRequests:
		return CodeTooManyRequests
	}
	if status >= http.StatusInternalServerError {
		return CodeInternal
	}
	return CodeInvalidRequest
}
