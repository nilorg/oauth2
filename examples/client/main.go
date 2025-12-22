package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/nilorg/oauth2"
	"github.com/nilorg/pkg/logger"
)

var (
	client *oauth2.Client

	// PKCE: 存储 code_verifier（实际应用中应存储在 session 中）
	// PKCE: store code_verifier (should be stored in session in real applications)
	pkceCodeVerifier string
)

func init() {
	logger.Init()
	client = oauth2.NewClient("http://localhost:8003", "oauth2_client", "password")
	client.Log = &oauth2.DefaultLogger{}
}

func main() {
	r := gin.Default()

	// ============= 授权码模式 (无 PKCE) =============
	// Authorization Code Grant (without PKCE)
	r.GET("/authorize", func(c *gin.Context) {
		err := client.AuthorizeAuthorizationCode(c.Request.Context(), c.Writer, "http://localhost:8080/callback", "read write", "state123")
		if err != nil {
			logger.Errorln(err)
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	})

	// ============= 授权码模式 + PKCE =============
	// Authorization Code Grant with PKCE (recommended for public clients)
	r.GET("/authorize-pkce", func(c *gin.Context) {
		// 生成 PKCE code_verifier 和 code_challenge
		// Generate PKCE code_verifier and code_challenge
		pkceCodeVerifier = oauth2.RandomCodeVerifier()
		codeChallenge := oauth2.GenerateCodeChallenge(pkceCodeVerifier, oauth2.CodeChallengeMethodS256)

		// 构建授权 URL
		// Build authorization URL
		authURL := fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
			"http://localhost:8003",
			client.ID,
			url.QueryEscape("http://localhost:8080/callback-pkce"),
			url.QueryEscape("read write"),
			"pkce_state",
			codeChallenge,
		)

		c.Redirect(http.StatusFound, authURL)
	})

	// ============= 回调处理 (无 PKCE) =============
	// Callback handler (without PKCE)
	r.GET("/callback", func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")
		errorParam := c.Query("error")

		if errorParam != "" {
			c.JSON(400, gin.H{
				"error":       errorParam,
				"description": c.Query("error_description"),
			})
			return
		}

		token, err := client.TokenAuthorizationCode(c.Request.Context(), code, "http://localhost:8080/callback", client.ID)
		if err != nil {
			c.JSON(400, gin.H{
				"error": err.Error(),
				"state": state,
			})
			return
		}

		c.JSON(200, gin.H{
			"message": "授权成功 / Authorization successful",
			"state":   state,
			"token":   token,
		})
	})

	// ============= 回调处理 + PKCE =============
	// Callback handler with PKCE
	r.GET("/callback-pkce", func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")
		errorParam := c.Query("error")

		if errorParam != "" {
			c.JSON(400, gin.H{
				"error":       errorParam,
				"description": c.Query("error_description"),
			})
			return
		}

		// 使用 code_verifier 换取 token
		// Exchange code for token using code_verifier
		token, err := tokenAuthorizationCodeWithPKCE(code, "http://localhost:8080/callback-pkce", pkceCodeVerifier)
		if err != nil {
			c.JSON(400, gin.H{
				"error": err.Error(),
				"state": state,
			})
			return
		}

		c.JSON(200, gin.H{
			"message": "PKCE 授权成功 / PKCE Authorization successful",
			"state":   state,
			"token":   token,
		})
	})

	// ============= 隐式模式 =============
	// Implicit Grant
	r.GET("/implicit", func(c *gin.Context) {
		err := client.AuthorizeImplicit(c.Request.Context(), c.Writer, "http://localhost:8080/implicit-callback", "read", "implicit_state")
		if err != nil {
			logger.Errorln(err)
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	})

	// ============= 密码模式 =============
	// Resource Owner Password Credentials Grant
	r.GET("/password", func(c *gin.Context) {
		token, err := client.TokenResourceOwnerPasswordCredentials(c.Request.Context(), "admin", "123456")
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{
			"message": "密码模式授权成功 / Password grant successful",
			"token":   token,
		})
	})

	// ============= 客户端凭证模式 =============
	// Client Credentials Grant
	r.GET("/client-credentials", func(c *gin.Context) {
		token, err := client.TokenClientCredentials(c.Request.Context(), "read")
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{
			"message": "客户端凭证模式授权成功 / Client credentials grant successful",
			"token":   token,
		})
	})

	// ============= 刷新令牌 =============
	// Refresh Token
	r.POST("/refresh", func(c *gin.Context) {
		refreshToken := c.PostForm("refresh_token")
		if refreshToken == "" {
			c.JSON(400, gin.H{"error": "refresh_token is required"})
			return
		}

		token, err := client.RefreshToken(c.Request.Context(), refreshToken)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{
			"message": "令牌刷新成功 / Token refresh successful",
			"token":   token,
		})
	})

	// ============= 设备授权模式 =============
	// Device Authorization Grant
	r.GET("/device", func(c *gin.Context) {
		err := client.DeviceAuthorization(c.Request.Context(), c.Writer, "read")
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
	})

	fmt.Println("=========================================")
	fmt.Println("OAuth2 Client started at :8080")
	fmt.Println("=========================================")
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  - GET  /authorize          授权码模式")
	fmt.Println("  - GET  /authorize-pkce     授权码模式 + PKCE (推荐)")
	fmt.Println("  - GET  /callback           授权码回调")
	fmt.Println("  - GET  /callback-pkce      PKCE 回调")
	fmt.Println("  - GET  /implicit           隐式模式")
	fmt.Println("  - GET  /password           密码模式")
	fmt.Println("  - GET  /client-credentials 客户端凭证模式")
	fmt.Println("  - POST /refresh            刷新令牌")
	fmt.Println("  - GET  /device             设备授权模式")
	fmt.Println("")
	fmt.Println("测试步骤 / Test Steps:")
	fmt.Println("  1. 启动 server: cd examples/server && go run main.go")
	fmt.Println("  2. 启动 client: cd examples/client && go run main.go")
	fmt.Println("  3. 访问 http://localhost:8080/password 测试密码模式")
	fmt.Println("  4. 访问 http://localhost:8080/client-credentials 测试客户端凭证模式")
	fmt.Println("  5. 访问 http://localhost:8080/authorize-pkce 测试 PKCE 授权码模式")
	fmt.Println("")

	r.Run(":8080")
}

// tokenAuthorizationCodeWithPKCE 使用 PKCE 换取令牌
// Exchange authorization code for token with PKCE
func tokenAuthorizationCodeWithPKCE(code, redirectURI, codeVerifier string) (*oauth2.TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {client.ID},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8003/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, client.Secret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp oauth2.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}
