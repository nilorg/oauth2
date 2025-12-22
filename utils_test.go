package oauth2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRequestClientBasic_BasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.SetBasicAuth("client_id", "client_secret")

	basic, err := RequestClientBasic(req)
	if err != nil {
		t.Fatalf("RequestClientBasic() error = %v", err)
	}
	if basic.ID != "client_id" {
		t.Errorf("RequestClientBasic() ID = %v, want %v", basic.ID, "client_id")
	}
	if basic.Secret != "client_secret" {
		t.Errorf("RequestClientBasic() Secret = %v, want %v", basic.Secret, "client_secret")
	}
}

func TestRequestClientBasic_PostForm(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.PostForm = map[string][]string{
		"client_id":     {"form_client_id"},
		"client_secret": {"form_client_secret"},
	}

	basic, err := RequestClientBasic(req)
	if err != nil {
		t.Fatalf("RequestClientBasic() error = %v", err)
	}
	if basic.ID != "form_client_id" {
		t.Errorf("RequestClientBasic() ID = %v, want %v", basic.ID, "form_client_id")
	}
	if basic.Secret != "form_client_secret" {
		t.Errorf("RequestClientBasic() Secret = %v, want %v", basic.Secret, "form_client_secret")
	}
}

func TestRequestClientBasic_NoCredentials(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/token", nil)

	_, err := RequestClientBasic(req)
	if err != ErrInvalidClient {
		t.Errorf("RequestClientBasic() error = %v, want %v", err, ErrInvalidClient)
	}
}

func TestRequestClientBasic_MissingSecret(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.PostForm = map[string][]string{
		"client_id": {"only_id"},
	}

	_, err := RequestClientBasic(req)
	if err != ErrInvalidClient {
		t.Errorf("RequestClientBasic() error = %v, want %v", err, ErrInvalidClient)
	}
}

func TestWriterJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}

	WriterJSON(w, data)

	if w.Code != http.StatusOK {
		t.Errorf("WriterJSON() status = %v, want %v", w.Code, http.StatusOK)
	}

	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("WriterJSON() result = %v, want %v", result["key"], "value")
	}
}

func TestWriterError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"InvalidRequest", ErrInvalidRequest, http.StatusBadRequest},
		{"InvalidClient", ErrInvalidClient, http.StatusUnauthorized},
		{"InvalidGrant", ErrInvalidGrant, http.StatusBadRequest},                 // RFC 6749 Section 5.2
		{"UnauthorizedClient", ErrUnauthorizedClient, http.StatusBadRequest},     // RFC 6749 Section 5.2
		{"UnsupportedGrantType", ErrUnsupportedGrantType, http.StatusBadRequest}, // RFC 6749 Section 5.2
		{"InvalidScope", ErrInvalidScope, http.StatusBadRequest},
		{"AccessDenied", ErrAccessDenied, http.StatusForbidden},
		{"UnsupportedResponseType", ErrUnsupportedResponseType, http.StatusBadRequest}, // RFC 6749 Section 4.1.2.1
		{"ServerError", ErrServerError, http.StatusInternalServerError},
		{"TemporarilyUnavailable", ErrTemporarilyUnavailable, http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			WriterError(w, tt.err)

			if w.Code != tt.wantStatus {
				t.Errorf("WriterError() status = %v, want %v", w.Code, tt.wantStatus)
			}

			var result ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}
			if result.Error != tt.err.Error() {
				t.Errorf("WriterError() error = %v, want %v", result.Error, tt.err.Error())
			}
		})
	}
}

func TestRedirectSuccess(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/authorize?state=test_state", nil)
	w := httptest.NewRecorder()

	redirectURI, _ := parseRedirectURI("http://localhost/callback")
	RedirectSuccess(w, req, redirectURI, "test_code")

	if w.Code != http.StatusFound {
		t.Errorf("RedirectSuccess() status = %v, want %v", w.Code, http.StatusFound)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatal("RedirectSuccess() Location header is empty")
	}
	if !contains(location, "code=test_code") {
		t.Errorf("RedirectSuccess() location should contain code=test_code, got %s", location)
	}
	if !contains(location, "state=test_state") {
		t.Errorf("RedirectSuccess() location should contain state=test_state, got %s", location)
	}
}

func TestRedirectError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/authorize?state=test_state", nil)
	w := httptest.NewRecorder()

	redirectURI, _ := parseRedirectURI("http://localhost/callback")
	RedirectError(w, req, redirectURI, ErrAccessDenied)

	if w.Code != http.StatusFound {
		t.Errorf("RedirectError() status = %v, want %v", w.Code, http.StatusFound)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatal("RedirectError() Location header is empty")
	}
	if !contains(location, "error=access_denied") {
		t.Errorf("RedirectError() location should contain error=access_denied, got %s", location)
	}
	if !contains(location, "state=test_state") {
		t.Errorf("RedirectError() location should contain state=test_state, got %s", location)
	}
}

func TestRandomState(t *testing.T) {
	state := RandomState()
	if len(state) != 6 {
		t.Errorf("RandomState() length = %v, want 6", len(state))
	}
	// 验证不同调用产生不同结果（概率测试）
	state2 := RandomState()
	if state == state2 {
		// 可能会相同，但概率很小，多次测试
		state3 := RandomState()
		state4 := RandomState()
		if state == state3 && state == state4 {
			t.Errorf("RandomState() seems not random")
		}
	}
}

func TestRandomCode(t *testing.T) {
	code := RandomCode()
	if len(code) != 12 {
		t.Errorf("RandomCode() length = %v, want 12", len(code))
	}
}

func TestRandomDeviceCode(t *testing.T) {
	code := RandomDeviceCode()
	if len(code) != 32 {
		t.Errorf("RandomDeviceCode() length = %v, want 32", len(code))
	}
}

func TestRandomUserCode(t *testing.T) {
	code := RandomUserCode()
	// 格式: XXX-XXX (7个字符)
	if len(code) != 7 {
		t.Errorf("RandomUserCode() length = %v, want 7", len(code))
	}
	if code[3] != '-' {
		t.Errorf("RandomUserCode() format should be XXX-XXX, got %s", code)
	}
}

func TestStringSplit(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		sep     string
		wantLen int
	}{
		{"空字符串", "", " ", 0},
		{"单个值", "read", " ", 1},
		{"多个值", "read write delete", " ", 3},
		{"逗号分隔", "a,b,c", ",", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringSplit(tt.s, tt.sep)
			if len(result) != tt.wantLen {
				t.Errorf("StringSplit() length = %v, want %v", len(result), tt.wantLen)
			}
		})
	}
}

// 辅助函数
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func parseRedirectURI(uri string) (*url.URL, error) {
	return url.Parse(uri)
}

// 使用标准库的 url.URL
