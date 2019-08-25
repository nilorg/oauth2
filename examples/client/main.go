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
