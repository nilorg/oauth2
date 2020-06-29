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
	srv.VerifyClient = func(basic *oauth2.ClientBasic) (err error) {
		pwd, ok := clients[basic.ID]
		if !ok {
			err = oauth2.ErrInvalidClient
			return
		}
		basic = &oauth2.ClientBasic{
			ID:     basic.ID,
			Secret: pwd,
		}
		return
	}
	srv.VerifyCode = func(code, clientID, redirectURI string) (value *oauth2.CodeValue, err error) {
		//err = oauth2.ErrUnauthorizedClient
		// 查询缓存/数据库中的code信息
		value = &oauth2.CodeValue{
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Scope:       []string{"a", "b", "c"},
		}
		return
	}
	srv.GenerateCode = func(clientID, openID, redirectURI string, scope []string) (code string, err error) {
		code = oauth2.RandomCode()
		return
	}
	srv.VerifyRedirectURI = func(clientID, redirectURI string) (err error) {
		fmt.Println(clientID)
		fmt.Println(redirectURI)
		// err = oauth2.ErrInvalidRedirectURI
		return
	}

	srv.VerifyPassword = func(username, password string) (openID string, err error) {
		if username != "a" || password != "b" {
			err = oauth2.ErrUnauthorizedClient
			return
		}
		openID = "xxxx"
		return
	}

	srv.VerifyScope = func(scopes []string, clientID string) (err error) {
		// err = oauth2.ErrInvalidScope
		return
	}

	srv.GenerateAccessToken = oauth2.NewDefaultGenerateAccessToken([]byte("xxxxx"))
	srv.RefreshAccessToken = oauth2.NewDefaultRefreshAccessToken([]byte("xxxxx"))
	srv.ParseAccessToken = oauth2.NewDefaultParseAccessToken([]byte("xxxxx"))

	srv.GenerateDeviceAuthorization = func(issuer, verificationURI, clientID, scope string) (resp *oauth2.DeviceAuthorizationResponse, err error) {
		resp = &oauth2.DeviceAuthorizationResponse{
			DeviceCode:            oauth2.RandomCode(),
			UserCode:              oauth2.RandomUserCode(),
			VerificationURI:       verificationURI,
			VerificationURIQrcode: "",
			ExpiresIn:             0,
			Interval:              5,
		}
		return
	}

	srv.VerifyDeviceCode = func(deviceCode, clientID string) (value *oauth2.DeviceCodeValue, err error) {
		// err = oauth2.ErrAuthorizationPending
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
		oauth2Group.POST("/device_authorization", func(c *gin.Context) {
			srv.HandleDeviceAuthorization(c.Writer, c.Request)
		})
	}

	if err := http.ListenAndServe(":8003", r); err != nil {
		fmt.Printf("%+v\n", err)
	}
}
