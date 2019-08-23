package main

import (
	"fmt"
	"github.com/nilorg/oauth2"
	"github.com/nilorg/oauth2/examples"
	"net/http"
)

var (
	clients = map[string]string{
		"oauth2_client": "password",
	}
)

func main() {
	srv := oauth2.NewServer(examples.NewDefaultService())
	srv.CheckClientBasic = func(basic *oauth2.ClientBasic) (err error) {
		pwd, ok := clients[basic.ID]
		if !ok {
			err = oauth2.ErrInvalidClient
		} else if basic.Secret != pwd {
			err = oauth2.ErrUnauthorizedClient
		}
		return
	}
	if err := http.ListenAndServe(":8003", srv); err != nil {
		fmt.Printf("%+v\n", err)
	}
}
