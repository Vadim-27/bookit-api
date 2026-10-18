// Package httpjson decodes JSON request bodies strictly. Every handler uses it,
// so the rules are the same everywhere.
package httpjson

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
)

// Decode reads the request body into dst, a pointer to a DTO struct. It is
// strict on purpose:
//   - the Content-Type must be application/json;
//   - the body is limited to maxBytes;
//   - unknown fields are rejected, not silently ignored (a client sending
//     "role": "owner" gets an error instead of being quietly ignored);
//   - nothing may follow the JSON object.
//
// The returned error is an *echo.HTTPError with a safe message for the client.
func Decode(c *echo.Context, dst any, maxBytes int64) error {
	if !isJSON(c.Request().Header.Get("Content-Type")) {
		return echo.NewHTTPError(http.StatusUnsupportedMediaType, "content type must be application/json")
	}

	body := http.MaxBytesReader(c.Response(), c.Request().Body, maxBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return decodeError(err)
		}
		return echo.NewHTTPError(http.StatusBadRequest, "request body must contain a single JSON object")
	}
	return nil
}

func isJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "application/json"
}

// decodeError turns a decoder error into a client error without leaking
// anything about the server.
func decodeError(err error) error {
	var tooLarge *http.MaxBytesError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &tooLarge):
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "request body is too large")
	case errors.Is(err, io.EOF):
		return echo.NewHTTPError(http.StatusBadRequest, "request body is empty")
	case errors.As(err, &typeErr):
		return echo.NewHTTPError(http.StatusBadRequest, "field "+typeErr.Field+" has the wrong type")
	case strings.HasPrefix(err.Error(), "json: unknown field"):
		return echo.NewHTTPError(http.StatusBadRequest, strings.TrimPrefix(err.Error(), "json: "))
	}
	return echo.NewHTTPError(http.StatusBadRequest, "request body is not valid JSON")
}
