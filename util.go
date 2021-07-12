package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"h12.io/socks"
)

func prepareProxy(proxyAddr string) fasthttp.DialFunc {
	if proxyAddr == ":" {
		return nil
	}
	proxyAddr = strings.ReplaceAll(proxyAddr, "|", ":")

	splittedProxy := strings.Split(proxyAddr, ":")
	switch len(splittedProxy) {
	case 3:
		proxyAddr = fmt.Sprintf("%s://%s:%s", strings.ToLower(splittedProxy[2]), splittedProxy[0], splittedProxy[1])
	case 5:
		proxyAddr = fmt.Sprintf("%s://%s:%s@%s:%s", strings.ToLower(splittedProxy[2]),
			splittedProxy[3],
			splittedProxy[4],
			splittedProxy[0],
			splittedProxy[1],
		)
	default:
		return nil
	}

	if strings.Contains(proxyAddr, "https") {
		return fasthttpproxy.FasthttpHTTPDialerTimeout(proxyAddr[8:], time.Second*4)
	} else {
		return func(addr string) (net.Conn, error) {
			dialer := socks.Dial(proxyAddr + "?timeout=4s")
			return dialer("tcp", addr)
		}
	}

}

func generateInstallID() string {
	id := make([]byte, 32)
	rand.Read(id)
	return hex.EncodeToString(id)
}
