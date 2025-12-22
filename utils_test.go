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

// PKCE 测试 (RFC 7636)

func TestVerifyCodeChallenge_S256(t *testing.T) {
	// 使用 RFC 7636 附录 B 中的示例
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// S256: BASE64URL(SHA256(code_verifier))
	codeChallenge := GenerateCodeChallenge(codeVerifier, CodeChallengeMethodS256)

	if !VerifyCodeChallenge(codeChallenge, CodeChallengeMethodS256, codeVerifier) {
		t.Error("VerifyCodeChallenge(S256) should return true for valid code_verifier")
	}

	// 错误的 code_verifier
	if VerifyCodeChallenge(codeChallenge, CodeChallengeMethodS256, "wrong_verifier") {
		t.Error("VerifyCodeChallenge(S256) should return false for invalid code_verifier")
	}
}

func TestVerifyCodeChallenge_Plain(t *testing.T) {
	codeVerifier := "test_code_verifier_1234567890"
	codeChallenge := codeVerifier // plain 方法下 challenge == verifier

	if !VerifyCodeChallenge(codeChallenge, CodeChallengeMethodPlain, codeVerifier) {
		t.Error("VerifyCodeChallenge(plain) should return true for matching verifier")
	}

	if VerifyCodeChallenge(codeChallenge, CodeChallengeMethodPlain, "wrong_verifier") {
		t.Error("VerifyCodeChallenge(plain) should return false for non-matching verifier")
	}
}

func TestVerifyCodeChallenge_NoChallenge(t *testing.T) {
	// 没有 code_challenge 时，验证应通过
	if !VerifyCodeChallenge("", "", "any_verifier") {
		t.Error("VerifyCodeChallenge() should return true when no code_challenge")
	}

	if !VerifyCodeChallenge("", "", "") {
		t.Error("VerifyCodeChallenge() should return true when both empty")
	}
}

func TestVerifyCodeChallenge_MissingVerifier(t *testing.T) {
	// 有 code_challenge 但没有 code_verifier
	if VerifyCodeChallenge("some_challenge", CodeChallengeMethodS256, "") {
		t.Error("VerifyCodeChallenge() should return false when code_verifier is missing")
	}
}

func TestVerifyCodeChallenge_DefaultMethod(t *testing.T) {
	// 空方法应默认使用 S256
	codeVerifier := "test_verifier_for_default_method"
	codeChallenge := GenerateCodeChallenge(codeVerifier, CodeChallengeMethodS256)

	if !VerifyCodeChallenge(codeChallenge, "", codeVerifier) {
		t.Error("VerifyCodeChallenge() should default to S256 when method is empty")
	}
}

func TestVerifyCodeChallenge_UnsupportedMethod(t *testing.T) {
	if VerifyCodeChallenge("challenge", "unsupported_method", "verifier") {
		t.Error("VerifyCodeChallenge() should return false for unsupported method")
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// S256
	s256Challenge := GenerateCodeChallenge(codeVerifier, CodeChallengeMethodS256)
	if s256Challenge == "" {
		t.Error("GenerateCodeChallenge(S256) should not return empty")
	}
	if s256Challenge == codeVerifier {
		t.Error("GenerateCodeChallenge(S256) should not equal code_verifier")
	}

	// Plain
	plainChallenge := GenerateCodeChallenge(codeVerifier, CodeChallengeMethodPlain)
	if plainChallenge != codeVerifier {
		t.Errorf("GenerateCodeChallenge(plain) = %v, want %v", plainChallenge, codeVerifier)
	}

	// 空方法默认为 S256
	defaultChallenge := GenerateCodeChallenge(codeVerifier, "")
	if defaultChallenge != s256Challenge {
		t.Error("GenerateCodeChallenge() should default to S256")
	}

	// 不支持的方法返回空
	unsupportedChallenge := GenerateCodeChallenge(codeVerifier, "unsupported")
	if unsupportedChallenge != "" {
		t.Error("GenerateCodeChallenge() should return empty for unsupported method")
	}
}

func TestRandomCodeVerifier(t *testing.T) {
	verifier := RandomCodeVerifier()

	// RFC 7636: code_verifier 长度应在 43-128 之间
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("RandomCodeVerifier() length = %v, want 43-128", len(verifier))
	}

	// 验证生成的 verifier 可以与 challenge 配合使用
	challenge := GenerateCodeChallenge(verifier, CodeChallengeMethodS256)
	if !VerifyCodeChallenge(challenge, CodeChallengeMethodS256, verifier) {
		t.Error("RandomCodeVerifier() should generate valid verifier")
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
