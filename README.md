# oauth2 (开发中...)


# Server

```go
package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/nilorg/oauth2"
	"net/http"
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
	//if err := http.ListenAndServe(":8003", srv); err != nil {
	//	fmt.Printf("%+v\n", err)
	//}

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