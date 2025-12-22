package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("http://localhost:8080", "client_id", "client_secret")

	if client.ServerBaseURL != "http://localhost:8080" {
		t.Errorf("NewClient() ServerBaseURL = %v, want %v", client.ServerBaseURL, "http://localhost:8080")
	}
	if client.ID != "client_id" {
		t.Errorf("NewClient() ID = %v, want %v", client.ID, "client_id")
	}
	if client.Secret != "client_secret" {
		t.Errorf("NewClient() Secret = %v, want %v", client.Secret, "client_secret")
	}
	if client.AuthorizationEndpoint != "/authorize" {
		t.Errorf("NewClient() AuthorizationEndpoint = %v, want %v", client.AuthorizationEndpoint, "/authorize")
	}
	if client.TokenEndpoint != "/token" {
		t.Errorf("NewClient() TokenEndpoint = %v, want %v", client.TokenEndpoint, "/token")
	}
	if client.DeviceAuthorizationEndpoint != "/device_authorization" {
		t.Errorf("NewClient() DeviceAuthorizationEndpoint = %v, want %v", client.DeviceAuthorizationEndpoint, "/device_authorization")
	}
	if client.IntrospectEndpoint != "/introspect" {
		t.Errorf("NewClient() IntrospectEndpoint = %v, want %v", client.IntrospectEndpoint, "/introspect")
	}
	if client.Log == nil {
		t.Error("NewClient() Log should not be nil")
	}
	if client.httpClient == nil {
		t.Error("NewClient() httpClient should not be nil")
	}
}

func TestClient_AuthorizeAuthorizationCode(t *testing.T) {
	// 创建一个模拟的OAuth2服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求参数
		if r.URL.Query().Get("response_type") != "code" {
			t.Errorf("response_type = %v, want code", r.URL.Query().Get("response_type"))
		}
		if r.URL.Query().Get("client_id") != "test_client" {
			t.Errorf("client_id = %v, want test_client", r.URL.Query().Get("client_id"))
		}
		// 模拟重定向
		http.Redirect(w, r, "http://localhost/callback?code=auth_code", http.StatusFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")
	w := httptest.NewRecorder()

	err := client.AuthorizeAuthorizationCode(context.Background(), w, "http://localhost/callback", "read write", "state123")
	if err != nil {
		t.Fatalf("AuthorizeAuthorizationCode() error = %v", err)
	}

	if w.Code != http.StatusFound {
		t.Errorf("AuthorizeAuthorizationCode() status = %v, want %v", w.Code, http.StatusFound)
	}
}

func TestClient_AuthorizeImplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("response_type") != "token" {
			t.Errorf("response_type = %v, want token", r.URL.Query().Get("response_type"))
		}
		http.Redirect(w, r, "http://localhost/callback#access_token=xxx", http.StatusFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")
	w := httptest.NewRecorder()

	err := client.AuthorizeImplicit(context.Background(), w, "http://localhost/callback", "read", "state")
	if err != nil {
		t.Fatalf("AuthorizeImplicit() error = %v", err)
	}
}

func TestClient_TokenAuthorizationCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %v, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %v, want authorization_code", r.FormValue("grant_type"))
		}
		if r.FormValue("code") != "test_code" {
			t.Errorf("code = %v, want test_code", r.FormValue("code"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "access_token_123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh_token_456",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")

	token, err := client.TokenAuthorizationCode(context.Background(), "test_code", "http://localhost/callback", "test_client")
	if err != nil {
		t.Fatalf("TokenAuthorizationCode() error = %v", err)
	}

	if token.AccessToken != "access_token_123" {
		t.Errorf("TokenAuthorizationCode() AccessToken = %v, want %v", token.AccessToken, "access_token_123")
	}
}

func TestClient_TokenResourceOwnerPasswordCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("grant_type") != "password" {
			t.Errorf("grant_type = %v, want password", r.FormValue("grant_type"))
		}
		if r.FormValue("username") != "testuser" {
			t.Errorf("username = %v, want testuser", r.FormValue("username"))
		}
		if r.FormValue("password") != "testpass" {
			t.Errorf("password = %v, want testpass", r.FormValue("password"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "ropc_token",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")

	token, err := client.TokenResourceOwnerPasswordCredentials(context.Background(), "testuser", "testpass")
	if err != nil {
		t.Fatalf("TokenResourceOwnerPasswordCredentials() error = %v", err)
	}

	if token.AccessToken != "ropc_token" {
		t.Errorf("TokenResourceOwnerPasswordCredentials() AccessToken = %v, want %v", token.AccessToken, "ropc_token")
	}
}

func TestClient_TokenClientCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %v, want client_credentials", r.FormValue("grant_type"))
		}

		// 验证Basic Auth
		username, password, ok := r.BasicAuth()
		if !ok {
			t.Error("Basic Auth not provided")
		}
		if username != "test_client" || password != "test_secret" {
			t.Errorf("Basic Auth = %v:%v, want test_client:test_secret", username, password)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "cc_token",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")

	token, err := client.TokenClientCredentials(context.Background(), "read")
	if err != nil {
		t.Fatalf("TokenClientCredentials() error = %v", err)
	}

	if token.AccessToken != "cc_token" {
		t.Errorf("TokenClientCredentials() AccessToken = %v, want %v", token.AccessToken, "cc_token")
	}
}

func TestClient_TokenClientCredentials_NoScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "cc_token_no_scope",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")

	token, err := client.TokenClientCredentials(context.Background())
	if err != nil {
		t.Fatalf("TokenClientCredentials() error = %v", err)
	}

	if token.AccessToken != "cc_token_no_scope" {
		t.Errorf("TokenClientCredentials() AccessToken = %v, want %v", token.AccessToken, "cc_token_no_scope")
	}
}

func TestClient_RefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %v, want refresh_token", r.FormValue("grant_type"))
		}
		if r.FormValue("refresh_token") != "old_refresh_token" {
			t.Errorf("refresh_token = %v, want old_refresh_token", r.FormValue("refresh_token"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			ExpiresIn:    3600,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")

	token, err := client.RefreshToken(context.Background(), "old_refresh_token")
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if token.AccessToken != "new_access_token" {
		t.Errorf("RefreshToken() AccessToken = %v, want %v", token.AccessToken, "new_access_token")
	}
}

func TestClient_TokenDeviceCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("grant_type") != "device_code" {
			t.Errorf("grant_type = %v, want device_code", r.FormValue("grant_type"))
		}
		if r.FormValue("device_code") != "test_device_code" {
			t.Errorf("device_code = %v, want test_device_code", r.FormValue("device_code"))
		}

		// device_code 不应该有 Basic Auth
		_, _, ok := r.BasicAuth()
		if ok {
			t.Error("device_code grant should not use Basic Auth")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "device_token",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")

	token, err := client.TokenDeviceCode(context.Background(), "test_device_code")
	if err != nil {
		t.Fatalf("TokenDeviceCode() error = %v", err)
	}

	if token.AccessToken != "device_token" {
		t.Errorf("TokenDeviceCode() AccessToken = %v, want %v", token.AccessToken, "device_token")
	}
}

func TestClient_DeviceAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("client_id") != "test_client" {
			t.Errorf("client_id = %v, want test_client", r.URL.Query().Get("client_id"))
		}
		if r.URL.Query().Get("scope") != "device" {
			t.Errorf("scope = %v, want device", r.URL.Query().Get("scope"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DeviceAuthorizationResponse{
			DeviceCode:      "device_123",
			UserCode:        "ABC-DEF",
			VerificationURI: "https://example.com/device",
			ExpiresIn:       1800,
			Interval:        5,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")
	w := httptest.NewRecorder()

	err := client.DeviceAuthorization(context.Background(), w, "device")
	if err != nil {
		t.Fatalf("DeviceAuthorization() error = %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("DeviceAuthorization() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestClient_TokenIntrospect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("token") != "test_token" {
			t.Errorf("token = %v, want test_token", r.FormValue("token"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(IntrospectionResponse{
			Active:   true,
			ClientID: "test_client",
			Username: "testuser",
			Scope:    "read write",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")
	client.IntrospectEndpoint = "/introspect"

	introspection, err := client.TokenIntrospect(context.Background(), "test_token")
	if err != nil {
		t.Fatalf("TokenIntrospect() error = %v", err)
	}

	if !introspection.Active {
		t.Error("TokenIntrospect() Active should be true")
	}
	if introspection.ClientID != "test_client" {
		t.Errorf("TokenIntrospect() ClientID = %v, want %v", introspection.ClientID, "test_client")
	}
}

func TestClient_TokenIntrospect_WithHint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("token_type_hint") != "access_token" {
			t.Errorf("token_type_hint = %v, want access_token", r.FormValue("token_type_hint"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(IntrospectionResponse{Active: true})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")

	_, err := client.TokenIntrospect(context.Background(), "test_token", "access_token")
	if err != nil {
		t.Fatalf("TokenIntrospect() error = %v", err)
	}
}

func TestClient_TokenIntrospect_InvalidHint(t *testing.T) {
	client := NewClient("http://localhost", "test_client", "test_secret")

	_, err := client.TokenIntrospect(context.Background(), "test_token", "invalid_hint")
	if err != ErrUnsupportedTokenType {
		t.Errorf("TokenIntrospect() error = %v, want %v", err, ErrUnsupportedTokenType)
	}
}

func TestClient_TokenRevocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("token") != "revoke_token" {
			t.Errorf("token = %v, want revoke_token", r.FormValue("token"))
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")
	client.TokenRevocationEndpoint = "/revoke"

	_, err := client.TokenRevocation(context.Background(), "revoke_token")
	if err != nil {
		t.Fatalf("TokenRevocation() error = %v", err)
	}
}

func TestClient_TokenRevocation_WithHint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("token_type_hint") != "refresh_token" {
			t.Errorf("token_type_hint = %v, want refresh_token", r.FormValue("token_type_hint"))
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")
	client.TokenRevocationEndpoint = "/revoke"

	_, err := client.TokenRevocation(context.Background(), "revoke_token", "refresh_token")
	if err != nil {
		t.Fatalf("TokenRevocation() error = %v", err)
	}
}

func TestClient_TokenRevocation_InvalidHint(t *testing.T) {
	client := NewClient("http://localhost", "test_client", "test_secret")

	_, err := client.TokenRevocation(context.Background(), "test_token", "invalid_hint")
	if err != ErrUnsupportedTokenType {
		t.Errorf("TokenRevocation() error = %v, want %v", err, ErrUnsupportedTokenType)
	}
}

func TestClient_Token_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "invalid_grant",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")

	_, err := client.TokenClientCredentials(context.Background())
	if err != ErrInvalidGrant {
		t.Errorf("TokenClientCredentials() error = %v, want %v", err, ErrInvalidGrant)
	}
}

func TestClient_Token_Custom(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if r.FormValue("grant_type") != "custom_grant" {
			t.Errorf("grant_type = %v, want custom_grant", r.FormValue("grant_type"))
		}
		if r.FormValue("custom_param") != "custom_value" {
			t.Errorf("custom_param = %v, want custom_value", r.FormValue("custom_param"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "custom_token",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test_client", "test_secret")

	values := map[string][]string{
		"custom_param": {"custom_value"},
	}
	token, err := client.Token(context.Background(), "custom_grant", values)
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	if token.AccessToken != "custom_token" {
		t.Errorf("Token() AccessToken = %v, want %v", token.AccessToken, "custom_token")
	}
}
