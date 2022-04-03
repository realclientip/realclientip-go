package realclientip_test

import (
	"fmt"
	"net/http"

	"github.com/realclientip/realclientip-go"
)

func Example_playground() {
	// We'll make a fake request
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Add("X-Forwarded-For", "1.1.1.1, 2001:db8:cafe::99%eth0, 3.3.3.3, 192.168.1.1")
	req.Header.Add("Forwarded", `For=fe80::abcd;By=fe80::1234, Proto=https;For=::ffff:188.0.2.128, For="[2001:db8:cafe::17]:4848", For=fc00::1`)
	req.Header.Add("X-Real-IP", "4.4.4.4")
	req.RemoteAddr = "192.168.1.2:8888"

	var strat realclientip.Strategy

	strat = realclientip.RemoteAddrStrategy{}
	fmt.Printf("\n%+v\n", strat)
	fmt.Println(strat.ClientIP(req.Header, req.RemoteAddr)) // 192.168.1.2

	strat, _ = realclientip.NewSingleIPHeaderStrategy("X-Real-IP")
	fmt.Printf("\n%+v\n", strat)
	fmt.Println(strat.ClientIP(req.Header, req.RemoteAddr)) // 4.4.4.4

	strat, _ = realclientip.NewLeftmostNonPrivateStrategy("Forwarded")
	fmt.Printf("\n%+v\n", strat)
	fmt.Println(strat.ClientIP(req.Header, req.RemoteAddr)) // 188.0.2.128

	strat, _ = realclientip.NewRightmostNonPrivateStrategy("X-Forwarded-For")
	fmt.Printf("\n%+v\n", strat)
	fmt.Println(strat.ClientIP(req.Header, req.RemoteAddr)) // 3.3.3.3

	strat, _ = realclientip.NewRightmostTrustedCountStrategy("Forwarded", 2)
	fmt.Printf("\n%+v\n", strat)
	fmt.Println(strat.ClientIP(req.Header, req.RemoteAddr)) // 2001:db8:cafe::17

	trustedRanges, _ := realclientip.AddressesAndRangesToIPNets([]string{"192.168.0.0/16", "3.3.3.3"}...)
	strat, _ = realclientip.NewRightmostTrustedRangeStrategy("X-Forwarded-For", trustedRanges)
	fmt.Printf("\n%+v\n", strat)
	fmt.Println(strat.ClientIP(req.Header, req.RemoteAddr)) // 2001:db8:cafe::99%eth0
	ipAddr, _ := realclientip.ParseIPAddr(strat.ClientIP(req.Header, req.RemoteAddr))
	fmt.Println(ipAddr.IP) // 2001:db8:cafe::99

	strat = realclientip.NewChainStrategy(
		realclientip.Must(realclientip.NewSingleIPHeaderStrategy("Cf-Connecting-IP")),
		realclientip.RemoteAddrStrategy{},
	)
	fmt.Printf("\n%+v\n", strat)
	fmt.Println(strat.ClientIP(req.Header, req.RemoteAddr)) // 192.168.1.2

	// Output:
	// {}
	// 192.168.1.2
	//
	// {headerName:X-Real-Ip}
	// 4.4.4.4
	//
	// {headerName:Forwarded}
	// 188.0.2.128
	//
	// {headerName:X-Forwarded-For}
	// 3.3.3.3
	//
	// {headerName:Forwarded trustedCount:2}
	// 2001:db8:cafe::17
	//
	// {headerName:X-Forwarded-For trustedRanges:[192.168.0.0/16 3.3.3.3/32]
	// 2001:db8:cafe::99%eth0
	// 2001:db8:cafe::99
	//
	// {strategies:[realclientip.SingleIPHeaderStrategy{headerName:Cf-Connecting-Ip} realclientip.RemoteAddrStrategy{}]}
	// 192.168.1.2
}
