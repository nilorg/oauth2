package main

import (
	"fmt"
	"github.com/nilorg/oauth2"
)

func main() {
	client := oauth2.NewClient("http://localhost:8003", "oauth2_client", "password")
	var err error
	var model *oauth2.TokenResponseModel
	model, err = client.TokenClientCredentials()
	if err != nil {
		fmt.Println("err:", err)
	} else {
		fmt.Println(model)
	}
}
