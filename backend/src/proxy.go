package main

import (
	"fmt"

	"github.com/inetaf/tcpproxy"
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
