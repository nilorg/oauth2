package main

import (
	"fmt"
	"net/http"
)

func main() {
	if err := http.ListenAndServe(":8003", NewServer(nil)); err != nil {
		fmt.Printf("%+v\n", err)
	}
}
