package oauth2

import (
	"encoding/json"
	"testing"
)

func TestCodeValue_MarshalBinary(t *testing.T) {
	code := &CodeValue{
		ClientID:    "client_123",
		OpenID:      "user_456",
		RedirectURI: "http://localhost/callback",
		Scope:       []string{"read", "write"},
	}

	data, err := code.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	// 验证是有效的JSON
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("MarshalBinary() produced invalid JSON: %v", err)
	}

	if result["client_id"] != "client_123" {
		t.Errorf("MarshalBinary() client_id = %v, want %v", result["client_id"], "client_123")
	}
}

func TestCodeValue_UnmarshalBinary(t *testing.T) {
	jsonData := []byte(`{"client_id":"client_123","open_id":"user_456","redirect_uri":"http://localhost/callback","scope":["read","write"]}`)

	code := &CodeValue{}
	if err := code.UnmarshalBinary(jsonData); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	if code.ClientID != "client_123" {
		t.Errorf("UnmarshalBinary() ClientID = %v, want %v", code.ClientID, "client_123")
	}
	if code.OpenID != "user_456" {
		t.Errorf("UnmarshalBinary() OpenID = %v, want %v", code.OpenID, "user_456")
	}
	if code.RedirectURI != "http://localhost/callback" {
		t.Errorf("UnmarshalBinary() RedirectURI = %v, want %v", code.RedirectURI, "http://localhost/callback")
	}
	if len(code.Scope) != 2 {
		t.Errorf("UnmarshalBinary() Scope length = %v, want %v", len(code.Scope), 2)
	}
}

func TestCodeValue_RoundTrip(t *testing.T) {
	original := &CodeValue{
		ClientID:    "test_client",
		OpenID:      "test_user",
		RedirectURI: "https://example.com/callback",
		Scope:       []string{"openid", "profile", "email"},
	}

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	restored := &CodeValue{}
	if err := restored.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	if original.ClientID != restored.ClientID {
		t.Errorf("RoundTrip ClientID = %v, want %v", restored.ClientID, original.ClientID)
	}
	if original.OpenID != restored.OpenID {
		t.Errorf("RoundTrip OpenID = %v, want %v", restored.OpenID, original.OpenID)
	}
	if original.RedirectURI != restored.RedirectURI {
		t.Errorf("RoundTrip RedirectURI = %v, want %v", restored.RedirectURI, original.RedirectURI)
	}
}

func TestDeviceCodeValue_MarshalBinary(t *testing.T) {
	code := &DeviceCodeValue{
		OpenID: "user_789",
		Scope:  []string{"device", "control"},
	}

	data, err := code.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("MarshalBinary() produced invalid JSON: %v", err)
	}

	if result["open_id"] != "user_789" {
		t.Errorf("MarshalBinary() open_id = %v, want %v", result["open_id"], "user_789")
	}
}

func TestDeviceCodeValue_UnmarshalBinary(t *testing.T) {
	jsonData := []byte(`{"open_id":"user_789","scope":["device","control"]}`)

	code := &DeviceCodeValue{}
	if err := code.UnmarshalBinary(jsonData); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	if code.OpenID != "user_789" {
		t.Errorf("UnmarshalBinary() OpenID = %v, want %v", code.OpenID, "user_789")
	}
	if len(code.Scope) != 2 {
		t.Errorf("UnmarshalBinary() Scope length = %v, want %v", len(code.Scope), 2)
	}
}

func TestDeviceCodeValue_RoundTrip(t *testing.T) {
	original := &DeviceCodeValue{
		OpenID: "device_user",
		Scope:  []string{"read", "write", "delete"},
	}

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	restored := &DeviceCodeValue{}
	if err := restored.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	if original.OpenID != restored.OpenID {
		t.Errorf("RoundTrip OpenID = %v, want %v", restored.OpenID, original.OpenID)
	}
	if len(original.Scope) != len(restored.Scope) {
		t.Errorf("RoundTrip Scope length = %v, want %v", len(restored.Scope), len(original.Scope))
	}
}

func TestClientBasic_Fields(t *testing.T) {
	basic := &ClientBasic{
		ID:     "my_client",
		Secret: "my_secret",
	}

	if basic.ID != "my_client" {
		t.Errorf("ClientBasic.ID = %v, want %v", basic.ID, "my_client")
	}
	if basic.Secret != "my_secret" {
		t.Errorf("ClientBasic.Secret = %v, want %v", basic.Secret, "my_secret")
	}
}

func TestTokenResponse_AllFields(t *testing.T) {
	resp := &TokenResponse{
		AccessToken:  "access_123",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh_456",
		Data:         map[string]string{"custom": "data"},
		Scope:        "read write",
		IDToken:      "id_token_789",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var restored TokenResponse
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if restored.AccessToken != "access_123" {
		t.Errorf("TokenResponse.AccessToken = %v, want %v", restored.AccessToken, "access_123")
	}
	if restored.TokenType != "Bearer" {
		t.Errorf("TokenResponse.TokenType = %v, want %v", restored.TokenType, "Bearer")
	}
	if restored.ExpiresIn != 3600 {
		t.Errorf("TokenResponse.ExpiresIn = %v, want %v", restored.ExpiresIn, 3600)
	}
}

func TestDeviceAuthorizationResponse_Fields(t *testing.T) {
	resp := &DeviceAuthorizationResponse{
		DeviceCode:              "device_code_123",
		UserCode:                "ABC-123",
		VerificationURI:         "https://example.com/device",
		VerificationURIComplete: "https://example.com/device?user_code=ABC-123",
		ExpiresIn:               1800,
		Interval:                5,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var restored DeviceAuthorizationResponse
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if restored.DeviceCode != "device_code_123" {
		t.Errorf("DeviceAuthorizationResponse.DeviceCode = %v, want %v", restored.DeviceCode, "device_code_123")
	}
	if restored.UserCode != "ABC-123" {
		t.Errorf("DeviceAuthorizationResponse.UserCode = %v, want %v", restored.UserCode, "ABC-123")
	}
}

func TestIntrospectionResponse_Fields(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		ClientID: "client_123",
		Username: "user@example.com",
		Scope:    "read write",
		Sub:      "user_456",
		Aud:      "api",
		Iss:      1234567890,
		Exp:      1234571490,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var restored IntrospectionResponse
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if restored.Active != true {
		t.Errorf("IntrospectionResponse.Active = %v, want %v", restored.Active, true)
	}
	if restored.ClientID != "client_123" {
		t.Errorf("IntrospectionResponse.ClientID = %v, want %v", restored.ClientID, "client_123")
	}
}

func TestErrorResponse_Fields(t *testing.T) {
	resp := &ErrorResponse{
		Error: "invalid_request",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if string(data) != `{"error":"invalid_request"}` {
		t.Errorf("ErrorResponse JSON = %v, want %v", string(data), `{"error":"invalid_request"}`)
	}
}
