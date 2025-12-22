package oauth2

import (
	"testing"
	"time"
)

// HS256 需要 32 字节密钥
var jwtTestKey = []byte("12345678901234567890123456789012")

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
	token, err := NewHS256JwtClaimsToken(&cl, jwtTestKey)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("token: %s", token)
}

func TestParseJwtToken(t *testing.T) {
	// 先生成一个新的 token 用于测试
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
	token, err := NewHS256JwtClaimsToken(&cl, jwtTestKey)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	tokenClaims, err := ParseHS256JwtClaimsToken(token, jwtTestKey)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("token: %+v", tokenClaims)
}
