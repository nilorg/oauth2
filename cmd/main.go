package main

import (
	"fmt"
	"github.com/nilorg/oauth2"
	"github.com/nilorg/oauth2/examples"
	"net/http"
)

func main() {
	if err := http.ListenAndServe(":8003", oauth2.NewServer(examples.NewDefaultService())); err != nil {
		fmt.Printf("%+v\n", err)
	}
}
