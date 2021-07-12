package main

import (
	"fmt"

	"github.com/valyala/fasthttp"
)

func authHandler(ctx *fasthttp.RequestCtx) {
	defer func() {
		n++
	}()

	query := ctx.QueryArgs()
	email := query.Peek("email")
	pwd := query.Peek("pwd")
	proxyAddr := query.Peek("proxy")

	client := Client{
		User: &User{
			Email:    string(email),
			Password: string(pwd),
		},
		Proxy: string(proxyAddr),
	}
	err := client.auth()
	if err != nil {
		switch err.Error() {
		case badPasswordError.Error():
			ctx.Response.Header.SetStatusCode(401)
			ctx.WriteString(badPasswordError.Error())
		default:
			ctx.Error(err.Error(), 500)
		}
		return
	}

	err = client.getSubscription()
	if err != nil {
		switch err.Error() {
		default:
			ctx.Error(err.Error(), 500)
		}
		return
	}
	fmt.Fprintf(ctx, `{"ovpn_username":"%s", "ovpn_password":"%s", "billing_cycle":%d, "auto_bill":%t, "expiration_time":%d, "status":"%s"}`, client.User.OvpnUsername, client.User.OvpnPassword, client.User.BillingCycle, client.User.AutoBill, client.User.ExpTime, client.User.Status)

}
