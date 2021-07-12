package main

import (
	"fmt"
	"time"

	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

var n = 0

func main() {
	r := router.New()
	r.GET("/auth", authHandler)
	fmt.Println("Server started...")
	go func() {
		for {
			fmt.Printf("\rRequest #%d", n)
			time.Sleep(time.Second * 1)
		}
	}()
	fasthttp.ListenAndServe(":9755", r.Handler)

}
