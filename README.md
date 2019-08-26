# oauth2 (开发中...)

# 文档参考
1. [《理解OAuth 2.0》阮一峰](http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)
2. [《RFC 6749》](http://www.rfcreader.com/#rfc6749)

### AuthorizationCode
授权码模式（authorization code）是功能最完整、流程最严密的授权模式。

它的特点就是通过客户端的后台服务器，与"服务提供商"的认证服务器进行互动。
### Implicit
简化模式（implicit grant type）不通过第三方应用程序的服务器，直接在浏览器中向认证服务器申请令牌，跳过了"授权码"这个步骤，因此得名。

所有步骤在浏览器中完成，令牌对访问者是可见的，且客户端不需要认证。
### ResourceOwnerPasswordCredentials
密码模式（Resource Owner Password Credentials Grant）中，用户向客户端提供自己的用户名和密码。

客户端使用这些信息，向"服务商提供商"索要授权。

在这种模式中，用户必须把自己的密码给客户端，但是客户端不得储存密码。

这通常用在用户对客户端高度信任的情况下，比如客户端是操作系统的一部分，或者由一个著名公司出品。

而认证服务器只有在其他授权模式无法执行的情况下，才能考虑使用这种模式。
### ClientCredentials
客户端模式（Client Credentials Grant）指客户端以自己的名义，而不是以用户的名义，向"服务提供商"进行认证。

严格地说，客户端模式并不属于OAuth框架所要解决的问题。

在这种模式中，用户直接向客户端注册，客户端以自己的名义要求"服务提供商"提供服务，其实不存在授权问题。

# Server

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nilorg/oauth2"
)

var (
	clients = map[string]string{
		"oauth2_client": "password",
	}
)

func main() {
	srv := oauth2.NewServer()
	srv.VerifyClient = func(clientID string) (basic *oauth2.ClientBasic, err error) {
		pwd, ok := clients[clientID]
		if !ok {
			err = oauth2.ErrInvalidClient
			return
		}
		basic = &oauth2.ClientBasic{
			ID:     clientID,
			Secret: pwd,
		}
		return
	}
	srv.VerifyCode = func(code, clientID, redirectUri string) (value *oauth2.CodeValue, err error) {
		//err = oauth2.ErrUnauthorizedClient
		// 查询缓存/数据库中的code信息
		value = &oauth2.CodeValue{
			ClientID:    clientID,
			RedirectUri: redirectUri,
			Scope:       []string{"a", "b", "c"},
		}
		return
	}
	srv.GenerateCode = func(clientID, redirectUri string, scope []string) (code string, err error) {
		code = oauth2.RandomCode()
		return
	}
	srv.VerifyAuthorization = func(clientID, redirectUri string, scope []string) (err error) {
		fmt.Println(clientID)
		fmt.Println(redirectUri)
		fmt.Println(scope)
		//err = oauth2.ErrUnauthorizedClient
		return
	}
	srv.VerifyCredentialsScope = func(clientID string, scope []string) (err error) {
		err = oauth2.ErrUnauthorizedClient
		return
	}
	srv.VerifyPassword = func(username, password string, scope []string) (err error) {
		if username != "a" || password != "b" {
			err = oauth2.ErrUnauthorizedClient
		}
		return
	}
	srv.Init()

	// =============Http Default=============
	// http.HandleFunc("/authorize", srv.HandleAuthorize)
	// http.HandleFunc("/token", srv.HandleToken)
	// if err := http.ListenAndServe(":8003", srv); err != nil {
	// 	fmt.Printf("%+v\n", err)
	// }

	// =============Gin=============
	r := gin.Default()
	oauth2Group := r.Group("/oauth2")
	{
		oauth2Group.GET("/authorize", func(c *gin.Context) {
			srv.HandleAuthorize(c.Writer, c.Request)
		})
		oauth2Group.POST("/token", func(c *gin.Context) {
			srv.HandleToken(c.Writer, c.Request)
		})
	}

	if err := http.ListenAndServe(":8003", r); err != nil {
		fmt.Printf("%+v\n", err)
	}
}
```

# Client

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/nilorg/oauth2"
	"github.com/nilorg/pkg/logger"
)

var (
	client *oauth2.Client
)

func init()  {
	logger.Init()
	client = oauth2.NewClient("http://localhost:8003", "oauth2_client", "password")
	client.Log = logger.Default()
}
func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		//err := client.AuthorizeImplicit(c.Writer, "http://localhost:8080/callback", "test", "aaaaa")
		//if err != nil {
		//	logger.Errorln(err)
		//	return
		//}
		err := client.AuthorizeAuthorizationCode(c.Writer, "http://localhost:8080/callback", "test", "bbbbb")
		if err != nil {
			logger.Errorln(err)
			return
		}
	})
	r.GET("/callback", func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")
		token, err := client.TokenAuthorizationCode(code, c.Request.URL.String(), state)
		if err != nil {
			c.JSON(200, gin.H{
				"message": "callback",
				"err":     err.Error(),
			})
		} else {
			c.JSON(200, gin.H{
				"message": "callback",
				"token":   token,
			})
		}
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}
```

# jwt playload
 
 标准中注册的声明 (建议但不强制使用) ：
 
 `iss`: jwt签发者
 
 `sub`: jwt所面向的用户
 
 `aud`: 接收jwt的一方
 
 `exp`: jwt的过期时间，这个过期时间必须要大于签发时间
 
 `nbf`: 定义在什么时间之前，该jwt都是不可用的.
 
 `iat`: jwt的签发时间
 
 `jti`: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
 
 公共的声明 ：
 公共的声明可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息.但不建议添加敏感信息，因为该部分在客户端可解密.
 
 私有的声明 ：
 私有声明是提供者和消费者所共同定义的声明，一般不建议存放敏感信息，因为base64是对称解密的，意味着该部分信息可以归类为明文信息。