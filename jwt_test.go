package oauth2

import (
	"testing"
	"time"
)

func TestGenerateToken(t *testing.T) {
	cl := JwtClaims{
		JwtStandardClaims: JwtStandardClaims{
			Subject:   "subject",
			Issuer:    "http://localhost:8080",
			NotBefore: time.Now().Unix(),
			Audience: []string{
				"oauth2-client-test",
			},
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}
	token, err := NewHS256JwtToken(&cl, []byte("test"))
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("token: %s", token)
}

func TestParseJwtToken(t *testing.T) {
	tokenClaims, err := ParseJwtToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsib2F1dGgyLWNsaWVudC10ZXN0Il0sImV4cCI6MTU4OTc4OTUyMCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwibmJmIjoxNTg5NzAzMTIwLCJzdWIiOiJzdWJqZWN0In0.D0h0tKcGf2t7FwE5tkxZ8zTLozUFHfteKFU6tuL3dWA", []byte("test"))
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("token: %+v", tokenClaims)
}
