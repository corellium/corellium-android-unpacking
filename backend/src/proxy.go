package main

import (
	"fmt"
	"math/rand"

	"github.com/google/tcpproxy"
)

var (
	p tcpproxy.Proxy
)

func proxy(address string, localPort int) (int, error) {
	var ret error

	go func() {
		p.AddRoute(fmt.Sprintf(":%d", localPort), tcpproxy.To(address))
		ret = p.Run()
	}()

	return localPort, ret
}

func proxyRandomLocal(address string) (int, error) {
	localPort := rand.Intn(9000) + 1000

	return proxy(address, localPort)
}
