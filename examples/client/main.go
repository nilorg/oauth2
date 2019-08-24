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
	model, err = client.RefreshToken(model.RefreshToken)
	//model, err = client.RefreshToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NjY2Njg0ODQsInN1YiI6InJlZnJlc2hfdG9rZW4iLCJPcGVuSUQiOiIiLCJDbGllbnRJRCI6IiIsIlVzZXJuYW1lIjoiIn0.1NTnHZu2z_If5_SvjMw-cxlrAZm6nls-3viPavkYrt8")
	if err != nil {
		fmt.Println("err:", err)
	} else {
		fmt.Println(model)
	}
}
