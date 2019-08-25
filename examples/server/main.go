package main

import (
	"fmt"
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
	if err := http.ListenAndServe(":8003", srv); err != nil {
		fmt.Printf("%+v\n", err)
	}
}
