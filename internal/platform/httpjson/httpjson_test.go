package httpjson_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Vadim-27/bookit-api/internal/platform/apierror"
	"github.com/Vadim-27/bookit-api/internal/platform/httpjson"
)

const maxBody = 64

type dto struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

// newEcho returns a server with one route that decodes a dto and echoes the name.
func newEcho() *echo.Echo {
	e := echo.New()
	e.HTTPErrorHandler = apierror.Handler
	e.POST("/x", func(c *echo.Context) error {
		var in dto
		if err := httpjson.Decode(c, &in, maxBody); err != nil {
			return err
		}
		return c.JSON(http.StatusOK, map[string]string{"name": in.Name})
	})
	return e
}

func TestDecode(t *testing.T) {
	t.Parallel()

	const jsonType = "application/json"
	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
		wantCode    string
		wantMessage string // substring; empty means not checked
	}{
		{"valid", jsonType, `{"name":"Anna","age":30}`, http.StatusOK, "", ""},
		{"charset parameter is fine", jsonType + "; charset=utf-8", `{"name":"Anna"}`, http.StatusOK, "", ""},
		{"empty object", jsonType, `{}`, http.StatusOK, "", ""},

		{"unknown field is rejected", jsonType, `{"name":"A","role":"owner"}`, http.StatusBadRequest, apierror.CodeInvalidRequest, `unknown field "role"`},
		{"second object after the first", jsonType, `{"name":"A"} {"name":"B"}`, http.StatusBadRequest, apierror.CodeInvalidRequest, "single JSON object"},
		{"garbage after the object", jsonType, `{"name":"A"} garbage`, http.StatusBadRequest, apierror.CodeInvalidRequest, ""},
		{"wrong type of a field", jsonType, `{"age":"thirty"}`, http.StatusBadRequest, apierror.CodeInvalidRequest, "age"},
		{"empty body", jsonType, ``, http.StatusBadRequest, apierror.CodeInvalidRequest, "empty"},
		{"broken json", jsonType, `{"name":`, http.StatusBadRequest, apierror.CodeInvalidRequest, "not valid JSON"},
		{"json array instead of an object", jsonType, `[1,2]`, http.StatusBadRequest, apierror.CodeInvalidRequest, ""},

		{"form content type", "application/x-www-form-urlencoded", `name=Anna`, http.StatusUnsupportedMediaType, apierror.CodeUnsupportedMediaType, ""},
		{"plain text content type", "text/plain", `{"name":"A"}`, http.StatusUnsupportedMediaType, apierror.CodeUnsupportedMediaType, ""},
		{"missing content type", "", `{"name":"A"}`, http.StatusUnsupportedMediaType, apierror.CodeUnsupportedMediaType, ""},
		{"lookalike content type", "application/jsonp", `{"name":"A"}`, http.StatusUnsupportedMediaType, apierror.CodeUnsupportedMediaType, ""},

		{"body over the limit", jsonType, `{"name":"` + strings.Repeat("a", maxBody) + `"}`, http.StatusRequestEntityTooLarge, apierror.CodeRequestTooLarge, "too large"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			newEcho().ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status: got %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantStatus == http.StatusOK {
				return
			}

			var body apierror.Body
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %q is not the error envelope: %v", rec.Body, err)
			}
			if body.Error.Code != tt.wantCode {
				t.Errorf("code: got %q, want %q", body.Error.Code, tt.wantCode)
			}
			if tt.wantMessage != "" && !strings.Contains(body.Error.Message, tt.wantMessage) {
				t.Errorf("message %q does not contain %q", body.Error.Message, tt.wantMessage)
			}
		})
	}
}
