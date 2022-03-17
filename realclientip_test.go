// SPDX: Unlicense

package realclientip

import (
	"fmt"
	"net"
	"net/http"
	"reflect"
	"testing"
)

/*
IP types and formats to test:

	IPv4 with no port
	192.0.2.60

	IPv4 with port
	192.0.2.60:4833

	IPv6 with no port
	2001:db8:cafe::17

	IPv6 with port
	[2001:db8:cafe::17]:4711

	IPv6 with zone and no port
	fe80::abcd%zone

	IPv6 with port and zone
	[fe80::abcd%zone]:4711

	IPv4-mapped IPv6
	::ffff:188.0.2.128

	IPv4-mapped IPv6 with port
	[::ffff:188.0.2.128]:48483

	IPv4-mapped IPv6 in IPv6 (hex) form
	::ffff:bc15:0006
	(this is 188.0.2.128; for an internal address use ::ffff:ac15:0006)

	NAT64 IPv4-mapped IPv6
	64:ff9b::188.0.2.128
	(net.ParseIP converts to 64:ff9b::bc00:280, but netip.ParseAddr doesn't)

	IPv4 loopback
	127.0.0.1

	IPv6 loopback
	::1

Forwarded header tests also require testing with quotes around full address.
*/

func ipAddrsEqual(a, b net.IPAddr) bool {
	return a.IP.Equal(b.IP) && a.Zone == b.Zone
}

func Test_parseForwardedListItem(t *testing.T) {
	mustParseIPAddrPtr := func(ipStr string) *net.IPAddr {
		res := MustParseIPAddr(ipStr)
		return &res
	}

	tests := []struct {
		name string
		fwd  string
		want *net.IPAddr
	}{
		{
			// This is the correct form for IPv6 wit port
			name: "IPv6 with port and quotes",
			fwd:  `For="[2001:db8:cafe::17]:4711"`,
			want: mustParseIPAddrPtr("2001:db8:cafe::17"),
		},
		{
			// This is the correct form for IP with no port
			name: "IPv6 with quotes, no brackets, and no port",
			fwd:  `for="2001:db8:cafe::17"`,
			want: mustParseIPAddrPtr("2001:db8:cafe::17"),
		},
		{
			// This is not strictly correct, but it will succeed as we don't check for quotes
			name: "IPv6 with port and no quotes",
			fwd:  `For=[2001:db8:cafe::17]:4711`,
			want: mustParseIPAddrPtr("2001:db8:cafe::17"),
		},
		{
			name: "IPv6 with port, quotes, and zone",
			fwd:  `For="[fe80::abcd%zone]:4711"`,
			want: mustParseIPAddrPtr("fe80::abcd%zone"),
		},
		{
			name: "IPv6 with zone, no quotes, no port",
			fwd:  `For="fe80::abcd%zone"`,
			want: mustParseIPAddrPtr("fe80::abcd%zone"),
		},
		{
			name: "Error: IPv6 with quotes, brackets and no port",
			fwd:  `fOR="[2001:db8:cafe::17]"`,
			want: nil,
		},
		{
			name: "Error: IPv6 with brackets, no quotes, and no port",
			fwd:  `FOR=[2001:db8:cafe::17]`,
			want: nil,
		},
		{
			name: "IPv4 with port",
			fwd:  `FoR=192.0.2.60:4711`,
			want: mustParseIPAddrPtr("192.0.2.60"),
		},
		{
			name: "IPv4 with no port",
			fwd:  `for=192.0.2.60`,
			want: mustParseIPAddrPtr("192.0.2.60"),
		},
		{
			name: "IPv4 with quotes",
			fwd:  `for="192.0.2.60"`,
			want: mustParseIPAddrPtr("192.0.2.60"),
		},
		{
			name: "IPv4 with port and quotes",
			fwd:  `for="192.0.2.60:4823"`,
			want: mustParseIPAddrPtr("192.0.2.60"),
		},
		{
			name: "Error: invalid IPv4",
			fwd:  `for=192.0.2.999`,
			want: nil,
		},
		{
			name: "Error: invalid IPv6",
			fwd:  `for="2001:db8:cafe::999999"`,
			want: nil,
		},
		{
			name: "Error: non-IP identifier",
			fwd:  `for="_test"`,
			want: nil,
		},
		{
			name: "Multiple IPv4 directives",
			fwd:  `by=1.1.1.1;for=2.2.2.2;host=myhost;proto=https`,
			want: mustParseIPAddrPtr("2.2.2.2"),
		},
		{
			name: "Multiple IPv6 directives",
			fwd:  `by=1::1;host=myhost;for=2::2;proto=https`,
			want: mustParseIPAddrPtr("2::2"),
		},
		{
			name: "Multiple mixed directives",
			fwd:  `by=1::1;host=myhost;proto=https;for=2.2.2.2`,
			want: mustParseIPAddrPtr("2.2.2.2"),
		},
		{
			name: "IPv4-mapped IPv6",
			fwd:  `for="::ffff:188.0.2.128"`,
			want: mustParseIPAddrPtr("188.0.2.128"),
		},
		{
			name: "IPv4-mapped IPv6 with port and quotes",
			fwd:  `for="[::ffff:188.0.2.128]:49428"`,
			want: mustParseIPAddrPtr("188.0.2.128"),
		},
		{
			name: "IPv4-mapped IPv6 in IPv6 form",
			fwd:  `for="0:0:0:0:0:ffff:bc15:0006"`,
			want: mustParseIPAddrPtr("188.21.0.6"),
		},
		{
			name: "NAT64 IPv4-mapped IPv6",
			fwd:  `for="64:ff9b::188.0.2.128"`,
			want: mustParseIPAddrPtr("64:ff9b::188.0.2.128"),
		},
		{
			name: "IPv4 loopback",
			fwd:  `for=127.0.0.1`,
			want: mustParseIPAddrPtr("127.0.0.1"),
		},
		{
			name: "IPv6 loopback",
			fwd:  `for="::1"`,
			want: mustParseIPAddrPtr("::1"),
		},
		{
			name: "Error: garbage",
			fwd:  "ads\x00jkl&#*(383fdljk",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseForwardedListItem(tt.fwd)

			if got == nil || tt.want == nil {
				if got != tt.want {
					t.Fatalf("parseForwardedListItem() = %v, want %v", got, tt.want)
				}
				return
			}

			if !ipAddrsEqual(*got, *tt.want) {
				t.Fatalf("parseForwardedListItem() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoteAddrStrategy(t *testing.T) {
	type args struct {
		headers    http.Header
		remoteAddr string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "IPv4 with port",
			args: args{
				remoteAddr: "2.2.2.2:1234",
			},
			want: "2.2.2.2",
		},
		{
			name: "IPv4 with no port",
			args: args{
				remoteAddr: "2.2.2.2",
			},
			want: "2.2.2.2",
		},
		{
			name: "IPv6 with port",
			args: args{
				remoteAddr: "[2001:db8:cafe::18]:3838",
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "IPv6 with no port",
			args: args{
				remoteAddr: "2001:db8:cafe::18",
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "IPv6 with zone and no port",
			args: args{
				remoteAddr: `fe80::1111%eth0`,
			},
			want: `fe80::1111%eth0`,
		},
		{
			name: "IPv6 with zone and port",
			args: args{
				remoteAddr: `[fe80::2222%eth0]:4848`,
			},
			want: `fe80::2222%eth0`,
		},
		{
			name: "IPv4-mapped IPv6",
			args: args{
				remoteAddr: "[::ffff:172.21.0.6]:4747",
			},
			// It is okay that this converts to the IPv4 format, since it's most important
			// that the respresentation be consistent. It might also be good that it does,
			// so that it will match the same plain IPv4 address.
			// net/netip.ParseAddr gives a different form: "::ffff:172.21.0.6"
			want: "172.21.0.6",
		},
		{
			name: "IPv4-mapped IPv6 in IPv6 form",
			args: args{
				remoteAddr: "0:0:0:0:0:ffff:bc15:0006",
			},
			// net/netip.ParseAddr gives a different form: "::ffff:188.21.0.6"
			want: "188.21.0.6",
		},
		{
			name: "NAT64 IPv4-mapped IPv6",
			args: args{
				remoteAddr: "[64:ff9b::188.0.2.128]:4747",
			},
			// net.ParseIP and net/netip.ParseAddr convert to this. This is fine, as it is
			// done consistently.
			want: "64:ff9b::bc00:280",
		},
		{
			name: "6to4 IPv4-mapped IPv6",
			args: args{
				remoteAddr: "[2002:c000:204::]:4747",
			},
			want: "2002:c000:204::",
		},
		{
			name: "IPv4 loopback",
			args: args{
				remoteAddr: "127.0.0.1",
			},
			want: "127.0.0.1",
		},
		{
			name: "IPv6 loopback",
			args: args{
				remoteAddr: "::1",
			},
			want: "::1",
		},
		{
			name: "Garbage header (unused)",
			args: args{
				headers:    http.Header{"X-Forwarded-For": []string{"!!!"}},
				remoteAddr: "2.2.2.2:1234",
			},
			want: "2.2.2.2",
		},
		{
			name: "Fail: empty RemoteAddr",
			args: args{
				remoteAddr: "",
			},
			want: "",
		},
		{
			name: "Fail: garbage RemoteAddr",
			args: args{
				remoteAddr: "ohno",
			},
			want: "",
		},
		{
			name: "Fail: zero RemoteAddr IP",
			args: args{
				remoteAddr: "0.0.0.0",
			},
			want: "",
		},
		{
			name: "Fail: unspecified RemoteAddr IP",
			args: args{
				remoteAddr: "::",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoteAddrStrategy(tt.args.headers, tt.args.remoteAddr); got != tt.want {
				t.Fatalf("RemoteAddrStrategy() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSingleIPHeaderStrategy(t *testing.T) {
	type args struct {
		headerName string
		headers    http.Header
		remoteAddr string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "IPv4 with port",
			args: args{
				headerName: "True-Client-IP",
				headers: http.Header{
					"X-Real-Ip":       []string{"1.1.1.1"},
					"True-Client-Ip":  []string{"2.2.2.2:49489"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "2.2.2.2",
		},
		{
			name: "IPv4 with no port",
			args: args{
				headerName: "X-Real-IP",
				headers: http.Header{
					"X-Real-Ip":       []string{"1.1.1.1"},
					"True-Client-Ip":  []string{"2.2.2.2:49489"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "1.1.1.1",
		},
		{
			name: "IPv6 with port",
			args: args{
				headerName: "X-Real-IP",
				headers: http.Header{
					"X-Real-Ip":       []string{"[2001:db8:cafe::18]:3838"},
					"True-Client-Ip":  []string{"2.2.2.2:49489"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "IPv6 with no port",
			args: args{
				headerName: "X-Real-IP",
				headers: http.Header{
					"X-Real-Ip":       []string{"2001:db8:cafe::19"},
					"True-Client-Ip":  []string{"2.2.2.2:49489"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "2001:db8:cafe::19",
		},
		{
			name: "IPv6 with zone and no port",
			args: args{
				headerName: "a-b-c-d",
				headers: http.Header{
					"X-Real-Ip":       []string{"2001:db8:cafe::19"},
					"A-B-C-D":         []string{"fe80::1111%zone"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "fe80::1111%zone",
		},
		{
			name: "IPv6 with zone and port",
			args: args{
				headerName: "a-b-c-d",
				headers: http.Header{
					"X-Real-Ip":       []string{"2001:db8:cafe::19"},
					"A-B-C-D":         []string{"[fe80::1111%zone]:4848"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "fe80::1111%zone",
		},
		{
			name: "IPv6 with brackets but no port",
			args: args{
				headerName: "x-real-ip",
				headers: http.Header{
					"X-Real-Ip":       []string{"2001:db8:cafe::19"},
					"A-B-C-D":         []string{"[fe80::1111%zone]:4848"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "2001:db8:cafe::19",
		},
		{
			name: "IP-mapped IPv6",
			args: args{
				headerName: "x-real-ip",
				headers: http.Header{
					"X-Real-Ip":       []string{"::ffff:172.21.0.6"},
					"A-B-C-D":         []string{"[fe80::1111%zone]:4848"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "172.21.0.6",
		},
		{
			name: "IPv4-mapped IPv6 in IPv6 form",
			args: args{
				headerName: "x-real-ip",
				headers: http.Header{
					"X-Real-Ip":       []string{"[64:ff9b::188.0.2.128]:4747"},
					"A-B-C-D":         []string{"[fe80::1111%zone]:4848"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "64:ff9b::bc00:280",
		},
		{
			name: "6to4 IPv4-mapped IPv6",
			args: args{
				headerName: "x-real-ip",
				headers: http.Header{
					"X-Real-Ip":       []string{"2002:c000:204::"},
					"A-B-C-D":         []string{"[fe80::1111%zone]:4848"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "2002:c000:204::",
		},
		{
			name: "IPv4 loopback",
			args: args{
				headerName: "x-real-ip",
				headers: http.Header{
					"X-Real-Ip":       []string{"127.0.0.1"},
					"A-B-C-D":         []string{"[fe80::1111%zone]:4848"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "127.0.0.1",
		},
		{
			name: "Fail: missing header",
			args: args{
				headerName: "x-real-ip",
				headers: http.Header{
					"A-B-C-D":         []string{"[fe80::1111%zone]:4848"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "",
		},
		{
			name: "Fail: garbage IP",
			args: args{
				headerName: "True-Client-Ip",
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"nope"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "",
		},
		{
			name: "Fail: zero IP",
			args: args{
				headerName: "True-Client-Ip",
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"0.0.0.0"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			want: "",
		},
		{
			name: "Error: empty header name",
			args: args{
				headerName: "",
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"2.2.2.2"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			wantErr: true,
		},
		{
			name: "Error: X-Forwarded-For header",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"2.2.2.2"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strat, err := SingleIPHeaderStrategy(tt.args.headerName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SingleIPHeaderStrategy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				// We can't continue
				return
			}

			got := strat(tt.args.headers, tt.args.remoteAddr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("strat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLeftmostNonPrivateStrategy(t *testing.T) {
	type args struct {
		headerName string
		headers    http.Header
		remoteAddr string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "IPv4 with port",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
			},
			want: "2.2.2.2",
		},
		{
			name: "IPv4 with no port",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`For=5.5.5.5`, `For=6.6.6.6`},
				},
			},
			want: "5.5.5.5",
		},
		{
			name: "IPv6 with port",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`[2001:db8:cafe::18]:3838, 3.3.3.3`, `4.4.4.4`},
				},
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "IPv6 with no port",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`Host=blah;For="2001:db8:cafe::18";Proto=https`},
				},
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "IPv6 with port and zone",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`For=[fe80::1111%zone], Host=blah;For="[2001:db8:cafe::18%zone]:9943";Proto=https`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "2001:db8:cafe::18%zone",
		},
		{
			name: "IPv6 with port and zone, no quotes",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`For=[fe80::1111%zone], Host=blah;For=[2001:db8:cafe::18%zone]:9943;Proto=https`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "2001:db8:cafe::18%zone",
		},
		{
			name: "IPv4-mapped IPv6",
			args: args{
				headerName: "x-forwarded-for",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`::ffff:188.0.2.128, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`Host=blah;For="7.7.7.7";Proto=https`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "188.0.2.128",
		},
		{
			name: "IPv4-mapped IPv6 with port",
			args: args{
				headerName: "x-forwarded-for",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`[::ffff:188.0.2.128]:48483, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`Host=blah;For="7.7.7.7";Proto=https`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "188.0.2.128",
		},
		{
			name: "IPv4-mapped IPv6 in IPv6 (hex) form",
			args: args{
				headerName: "forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`[::ffff:188.0.2.128]:48483, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "188.21.0.6",
		},
		{
			name: "NAT64 IPv4-mapped IPv6",
			args: args{
				headerName: "x-forwarded-for",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`64:ff9b::188.0.2.128, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "64:ff9b::bc00:280",
		},
		{
			name: "XFF: leftmost not desirable",
			args: args{
				headerName: "x-forwarded-for",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`::1, nope`, `4.4.4.4, 5.5.5.5`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "4.4.4.4",
		},
		{
			name: "Forwarded: leftmost not desirable",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`::1, nope`, `4.4.4.4, 5.5.5.5`},
					"Forwarded":       []string{`For="", For="::ffff:192.168.1.1"`, `host=what;for=:48485;proto=https,For="2001:db8:cafe::18"`},
				},
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "Fail: XFF: none acceptable",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`::1, nope, ::, 0.0.0.0`, `192.168.1.1, !?!`},
					"Forwarded":       []string{`For="", For="::ffff:192.168.1.1"`, `host=what;for=:48485;proto=https,For="fe80::abcd%zone"`},
				},
			},
			want: "",
		},
		{
			name: "Fail: Forwarded: none acceptable",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`::1, nope`, `192.168.1.1, 2.2.2.2`},
					"Forwarded":       []string{`For="", For="::ffff:192.168.1.1"`, `host=what;for=:48485;proto=https,For="::ffff:ac15:0006%zone",For="::",For=0.0.0.0`},
				},
			},
			want: "",
		},
		{
			name: "Fail: XFF: no header",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip": []string{`1.1.1.1`},
					"Forwarded": []string{`For="", For="::ffff:192.168.1.1"`, `host=what;for=:48485;proto=https,For="::ffff:ac15:0006%zone"`},
				},
			},
			want: "",
		},
		{
			name: "Fail: Forwarded: no header",
			args: args{
				headerName: "forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`64:ff9b::188.0.2.128, 3.3.3.3`, `4.4.4.4`},
				},
			},
			want: "",
		},
		{
			name: "Error: empty header name",
			args: args{
				headerName: "",
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"2.2.2.2"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			wantErr: true,
		},
		{
			name: "Error: invalid header",
			args: args{
				headerName: "X-Real-IP",
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"2.2.2.2"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strat, err := LeftmostNonPrivateStrategy(tt.args.headerName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LeftmostNonPrivateStrategy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				// We can't continue
				return
			}

			got := strat(tt.args.headers, tt.args.remoteAddr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("strat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRightmostNonPrivateStrategy(t *testing.T) {
	type args struct {
		headerName string
		headers    http.Header
		remoteAddr string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "IPv4 with port",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4:39333`},
				},
			},
			want: "4.4.4.4",
		},
		{
			name: "IPv4 with no port",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`For=5.5.5.5`, `For=6.6.6.6`},
				},
			},
			want: "6.6.6.6",
		},
		{
			name: "IPv6 with port",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`[2001:db8:cafe::18]:3838`},
				},
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "IPv6 with no port",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`host=what;for=6.6.6.6;proto=https`, `Host=blah;For="2001:db8:cafe::18";Proto=https`},
				},
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "IPv6 with port and zone",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`host=what;for=6.6.6.6;proto=https`, `For="[2001:db8:cafe::18%eth0]:3393";Proto=https`, `Host=blah;For="[fe80::1111%zone]:9943";Proto=https`},
				},
			},
			want: "2001:db8:cafe::18%eth0",
		},
		{
			name: "IPv6 with port and zone, no quotes",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`host=what;for=6.6.6.6;proto=https`, `For="[2001:db8:cafe::18%eth0]:3393";Proto=https`, `Host=blah;For=[fe80::1111%zone]:9943;Proto=https`},
				},
			},
			want: "2001:db8:cafe::18%eth0",
		},
		{
			name: "IPv4-mapped IPv6",
			args: args{
				headerName: "x-forwarded-for",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`3.3.3.3`, `4.4.4.4, ::ffff:188.0.2.128`},
					"Forwarded":       []string{`Host=blah;For="7.7.7.7";Proto=https`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "188.0.2.128",
		},
		{
			name: "IPv4-mapped IPv6 with port",
			args: args{
				headerName: "x-forwarded-for",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`3.3.3.3`, `4.4.4.4,[::ffff:188.0.2.128]:48483`},
					"Forwarded":       []string{`Host=blah;For="7.7.7.7";Proto=https`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "188.0.2.128",
		},
		{
			name: "IPv4-mapped IPv6 in IPv6 (hex) form",
			args: args{
				headerName: "forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`[::ffff:188.0.2.128]:48483, 3.3.3.3`, `4.4.4.4`},
					"Forwarded":       []string{`host=what;for=6.6.6.6;proto=https`, `For="::ffff:bc15:0006"`},
				},
			},
			want: "188.21.0.6",
		},
		{
			name: "NAT64 IPv4-mapped IPv6",
			args: args{
				headerName: "x-forwarded-for",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`3.3.3.3`, `4.4.4.4, 64:ff9b::188.0.2.128`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "64:ff9b::bc00:280",
		},
		{
			name: "XFF: rightmost not desirable",
			args: args{
				headerName: "x-forwarded-for",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`4.4.4.4, 5.5.5.5`, `::1, nope`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "5.5.5.5",
		},
		{
			name: "Forwarded: rightmost not desirable",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`::1, nope`, `4.4.4.4, 5.5.5.5`},
					"Forwarded":       []string{`host=what;for=:48485;proto=https,For=2.2.2.2`, `For="", For="::ffff:192.168.1.1"`},
				},
			},
			want: "2.2.2.2",
		},
		{
			name: "Fail: XFF: none acceptable",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`::1, nope`, `192.168.1.1, !?!, ::, 0.0.0.0`},
					"Forwarded":       []string{`For="", For="::ffff:192.168.1.1"`, `host=what;for=:48485;proto=https,For="fe80::abcd%zone"`},
				},
			},
			want: "",
		},
		{
			name: "Fail: Forwarded: none acceptable",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`::1, nope`, `192.168.1.1, 2.2.2.2`},
					"Forwarded":       []string{`For="", For="::ffff:192.168.1.1"`, `host=what;for=:48485;proto=https,For="::ffff:ac15:0006%zone", For="::", For=0.0.0.0`},
				},
			},
			want: "",
		},
		{
			name: "Fail: XFF: no header",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip": []string{`1.1.1.1`},
					"Forwarded": []string{`For="", For="::ffff:192.168.1.1"`, `host=what;for=:48485;proto=https,For="::ffff:ac15:0006%zone"`},
				},
				remoteAddr: "9.9.9.9",
			},
			want: "",
		},
		{
			name: "Fail: Forwarded: no header",
			args: args{
				headerName: "forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`64:ff9b::188.0.2.128, 3.3.3.3`, `4.4.4.4`},
				},
			},
			want: "",
		},
		{
			name: "Error: empty header name",
			args: args{
				headerName: "",
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"2.2.2.2"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			wantErr: true,
		},
		{
			name: "Error: invalid header",
			args: args{
				headerName: "X-Real-IP",
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"2.2.2.2"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strat, err := RightmostNonPrivateStrategy(tt.args.headerName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RightmostNonPrivateStrategy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				// We can't continue
				return
			}

			got := strat(tt.args.headers, tt.args.remoteAddr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("strat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRightmostTrustedCountStrategy(t *testing.T) {
	type args struct {
		headerName   string
		trustedCount int
		headers      http.Header
		remoteAddr   string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Is it okay not to test every IP type, since the logic is sufficiently similar to RightmostNonPrivateStrategy?

		{
			name: "Count one",
			args: args{
				headerName:   "Forwarded",
				trustedCount: 1,
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`4.4.4.4, 5.5.5.5`, `::1, fe80::382b:141b:fa4a:2a16%28`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "6.6.6.6",
		},
		{
			name: "Count five",
			args: args{
				headerName:   "X-Forwarded-For",
				trustedCount: 5,
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`4.4.4.4, 5.5.5.5`, `::1, fe80::382b:141b:fa4a:2a16%28`, `7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10,11.11.11.11, 12.12.12.12`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "8.8.8.8",
		},
		{
			name: "Fail: header too short/count too large",
			args: args{
				headerName:   "X-Forwarded-For",
				trustedCount: 50,
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`4.4.4.4, 5.5.5.5`, `::1, fe80::382b:141b:fa4a:2a16%28`, `7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10,11.11.11.11, 12.12.12.12`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "",
		},
		{
			name: "Fail: bad value at count index",
			args: args{
				headerName:   "Forwarded",
				trustedCount: 2,
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`4.4.4.4, 5.5.5.5`, `::1, fe80::382b:141b:fa4a:2a16%28`, `7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10,11.11.11.11, 12.12.12.12`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `For=nope`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "",
		},
		{
			name: "Fail: zero value at count index",
			args: args{
				headerName:   "Forwarded",
				trustedCount: 2,
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`4.4.4.4, 5.5.5.5`, `::1, fe80::382b:141b:fa4a:2a16%28`, `7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10,11.11.11.11, 12.12.12.12`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `For=0.0.0.0`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			want: "",
		},
		{
			name: "Fail: header missing",
			args: args{
				headerName:   "Forwarded",
				trustedCount: 1,
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`4.4.4.4, 5.5.5.5`, `::1, fe80::382b:141b:fa4a:2a16%28`, `7.7.7.7.7, 8.8.8.8, 9.9.9.9, 10.10.10.10,11.11.11.11, 12.12.12.12`},
				},
			},
			want: "",
		},
		{
			name: "Error: empty header name",
			args: args{
				headerName:   "",
				trustedCount: 1,
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"2.2.2.2"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			wantErr: true,
		},
		{
			name: "Error: invalid header",
			args: args{
				headerName:   "X-Real-IP",
				trustedCount: 1,
				headers: http.Header{
					"X-Real-Ip":       []string{"::1"},
					"True-Client-Ip":  []string{"2.2.2.2"},
					"X-Forwarded-For": []string{"3.3.3.3"}},
			},
			wantErr: true,
		},
		{
			name: "Error: zero trustedCount",
			args: args{
				headerName:   "x-forwarded-for",
				trustedCount: 0,
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`4.4.4.4, 5.5.5.5`, `::1, nope`, `fe80::382b:141b:fa4a:2a16%28`},
					"Forwarded":       []string{`For="::ffff:bc15:0006"`, `host=what;for=6.6.6.6;proto=https`},
				},
			},
			wantErr: true,
		},
		{
			name: "Error: negative trustedCount",
			args: args{
				headerName:   "X-Forwarded-For",
				trustedCount: -999,
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4:39333`},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strat, err := RightmostTrustedCountStrategy(tt.args.headerName, tt.args.trustedCount)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RightmostTrustedCountStrategy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				// We can't continue
				return
			}

			got := strat(tt.args.headers, tt.args.remoteAddr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("strat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAddressesAndRangesToIPNets(t *testing.T) {
	tests := []struct {
		name    string
		ranges  []string
		want    []string
		wantErr bool
	}{
		{
			name:   "Empty input",
			ranges: []string{},
			want:   nil,
		},
		{
			name:   "Single IPv4 address",
			ranges: []string{"1.1.1.1"},
			want:   []string{"1.1.1.1/32"},
		},
		{
			name:   "Single IPv6 address",
			ranges: []string{"2001:db8:cafe::17"},
			want:   []string{"2001:db8:cafe::17/128"},
		},
		{
			name:   "Single IPv4 range",
			ranges: []string{"1.1.1.1/16"},
			want:   []string{"1.1.0.0/16"},
		},
		{
			name:   "Single IPv6 range",
			ranges: []string{"2001:db8:cafe::17/48"},
			want:   []string{"2001:db8:cafe::/48"},
		},
		{
			name: "Mixed input",
			ranges: []string{
				"1.1.1.1", "2001:db8:cafe::17",
				"1.1.1.1/32", "2001:db8:cafe::17/128",
				"1.1.1.1/16", "2001:db8:cafe::17/48",
				"::ffff:188.0.2.128/112", "::ffff:bc15:0006/104",
				"64:ff9b::188.0.2.128/112",
			},
			want: []string{
				"1.1.1.1/32", "2001:db8:cafe::17/128",
				"1.1.1.1/32", "2001:db8:cafe::17/128",
				"1.1.0.0/16", "2001:db8:cafe::/48",
				"188.0.0.0/16", "188.0.0.0/8",
				"64:ff9b::bc00:0/112",
			},
		},
		{
			name:   "No input",
			ranges: nil,
			want:   nil,
		},
		{
			name:    "Error: garbage CIDR",
			ranges:  []string{"2001:db8:cafe::17/nope"},
			wantErr: true,
		},
		{
			name:    "Error: CIDR with zone",
			ranges:  []string{"fe80::abcd%nope/64"},
			wantErr: true,
		},
		{
			name:    "Error: garbage IP",
			ranges:  []string{"1.1.1.nope"},
			wantErr: true,
		},
		{
			name:    "Error: empty value",
			ranges:  []string{""},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddressesAndRangesToIPNets(tt.ranges...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AddressesAndRangesToIPNets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				// We can't continue
				return
			}

			if len(got) != len(tt.want) {
				t.Fatalf("len mismatch: %d != %d", len(got), len(tt.want))
			}

			for i := 0; i < len(got); i++ {
				if got[i].String() != tt.want[i] {
					t.Fatalf("got does not equal want; %d: %q != %q", i, got[i].String(), tt.want[i])
				}
			}
		})
	}
}

func TestRightmostTrustedRangeStrategy(t *testing.T) {
	type args struct {
		headerName    string
		headers       http.Header
		remoteAddr    string
		trustedRanges []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "No ranges",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
				trustedRanges: nil,
			},
			want: "4.4.4.4",
		},
		{
			name: "One range",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
				trustedRanges: []string{`4.4.4.0/24`},
			},
			want: "3.3.3.3",
		},
		{
			name: "One IP",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
				trustedRanges: []string{`4.4.4.4`},
			},
			want: "3.3.3.3",
		},
		{
			name: "Many kinds of ranges",
			args: args{
				headerName: "Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
					"Forwarded": []string{
						`For=99.99.99.99, For=4.4.4.8, For="[2001:db8:cafe::17]:4747"`,
						`For=2.2.2.2:8883, For=64:ff9b::188.0.2.200, For=3.3.5.5, For=2001:db7::abcd`,
					},
				},
				trustedRanges: []string{
					`2.2.2.2/32`, `2001:db8:cafe::17/128`,
					`3.3.0.0/16`, `2001:db7::/64`,
					`::ffff:4.4.4.4/124`, `64:ff9b::188.0.2.128/112`,
				},
			},
			want: "99.99.99.99",
		},
		{
			name: "Cloudflare ranges",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`, `2400:cb00::1`},
				},
				trustedRanges: CloudflareIPRanges,
			},
			want: "4.4.4.4",
		},
		{
			name: "Fail: no non-trusted IP",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 2.2.2.3`, `2.2.2.4`},
				},
				trustedRanges: []string{`2.2.2.0/24`},
			},
			want: "",
		},
		{
			name: "Fail: rightmost non-trusted IP invalid",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`nope, 2.2.2.2:3384, 2.2.2.3`, `2.2.2.4`},
				},
				trustedRanges: []string{`2.2.2.0/24`},
			},
			want: "",
		},
		{
			name: "Fail: rightmost non-trusted IP unspecified",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`::, 2.2.2.2:3384, 2.2.2.3`, `2.2.2.4`},
				},
				trustedRanges: []string{`2.2.2.0/24`},
			},
			want: "",
		},
		{
			name: "Fail: no values in header",
			args: args{
				headerName: "X-Forwarded-For",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{}},
				trustedRanges: []string{`2.2.2.0/24`},
			},
			want: "",
		},
		{
			name: "Error: empty header nanme",
			args: args{
				headerName: "",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
				trustedRanges: nil,
			},
			wantErr: true,
		},
		{
			name: "Error: bad header nanme",
			args: args{
				headerName: "Not-XFF-Or-Forwarded",
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
				trustedRanges: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges, err := AddressesAndRangesToIPNets(tt.args.trustedRanges...)
			if err != nil {
				// We're not testing AddressesAndRangesToIPNets here
				t.Fatalf("AddressesAndRangesToIPNets failed")
			}

			strat, err := RightmostTrustedRangeStrategy(tt.args.headerName, ranges)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RightmostTrustedRangeStrategy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				// We can't continue
				return
			}

			got := strat(tt.args.headers, tt.args.remoteAddr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("strat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChainStrategies(t *testing.T) {
	type args struct {
		strategies []Strategy
		headers    http.Header
		remoteAddr string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Single strategy",
			args: args{
				strategies: []Strategy{RemoteAddrStrategy},
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
				remoteAddr: `5.5.5.5`,
			},
			want: "5.5.5.5",
		},
		{
			name: "Multiple strategies",
			args: args{
				strategies: []Strategy{
					Must(RightmostNonPrivateStrategy("Forwarded")),
					Must(SingleIPHeaderStrategy("true-client-ip")),
					Must(SingleIPHeaderStrategy("x-real-ip")),
					RemoteAddrStrategy,
				},
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
				remoteAddr: `5.5.5.5`,
			},
			want: "1.1.1.1",
		},
		{
			name: "Fail: No strategies",
			args: args{
				strategies: nil,
				headers: http.Header{
					"X-Real-Ip":       []string{`1.1.1.1`},
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
				remoteAddr: `5.5.5.5`,
			},
			want: "",
		},
		{
			name: "Fail: Multiple strategies, all fail",
			args: args{
				strategies: []Strategy{
					Must(RightmostNonPrivateStrategy("Forwarded")),
					Must(SingleIPHeaderStrategy("true-client-ip")),
					Must(SingleIPHeaderStrategy("x-real-ip")),
					RemoteAddrStrategy,
				},
				headers: http.Header{
					"X-Forwarded-For": []string{`2.2.2.2:3384, 3.3.3.3`, `4.4.4.4`},
				},
				remoteAddr: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strat := ChainStrategies(tt.args.strategies...)

			got := strat(tt.args.headers, tt.args.remoteAddr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("strat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMust(t *testing.T) {
	// We test the non-panic path elsewhere, but we need to specifically check the panic case
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("Must() did not panic")
		}
	}()

	Must(RemoteAddrStrategy, fmt.Errorf("oh no"))
}

func TestMustParseIPAddr(t *testing.T) {
	// We test the non-panic path elsewhere, but we need to specifically check the panic case
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("MustParseIPAddr() did not panic")
		}
	}()

	MustParseIPAddr("nope")
}

func TestParseIPAddr(t *testing.T) {
	tests := []struct {
		name    string
		ipStr   string
		want    net.IPAddr
		wantErr bool
	}{
		{
			name:  "Empty zone",
			ipStr: "1.1.1.1%",
			want:  net.IPAddr{IP: net.ParseIP("1.1.1.1"), Zone: ""},
		},
		{
			name:  "No zone",
			ipStr: "1.1.1.1",
			want:  net.IPAddr{IP: net.ParseIP("1.1.1.1"), Zone: ""},
		},
		{
			name:  "With zone",
			ipStr: "fe80::abcd%zone",
			want:  net.IPAddr{IP: net.ParseIP("fe80::abcd"), Zone: "zone"},
		},
		{
			name:  "With zone and port",
			ipStr: "[2001:db8:cafe::17%zone]:4484",
			want:  net.IPAddr{IP: net.ParseIP("2001:db8:cafe::17"), Zone: "zone"},
		},
		{
			name:  "With port",
			ipStr: "1.1.1.1:48944",
			want:  net.IPAddr{IP: net.ParseIP("1.1.1.1"), Zone: ""},
		},
		{
			name:  "Bad port (is discarded)",
			ipStr: "[fe80::abcd%eth0]:xyz",
			want:  net.IPAddr{IP: net.ParseIP("fe80::abcd"), Zone: "eth0"},
		},
		{
			name:  "Zero address",
			ipStr: "0.0.0.0",
			want:  net.IPAddr{IP: net.ParseIP("0.0.0.0"), Zone: ""},
		},
		{
			name:  "Unspecified address",
			ipStr: "::",
			want:  net.IPAddr{IP: net.ParseIP("::"), Zone: ""},
		},
		{
			name:    "Error: bad IP with zone",
			ipStr:   "nope%zone",
			wantErr: true,
		},
		{
			name:    "Error: bad IP",
			ipStr:   "nope!!",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPAddr(tt.ipStr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseIPAddr() error = %v, wantErr %v, got = %v", err, tt.wantErr, got)
				return
			}

			if !ipAddrsEqual(got, tt.want) {
				t.Fatalf("ParseIPAddr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_goodIPAddr(t *testing.T) {
	// This is mostly a copy of TestParseIPAddr, except that zero and unspecified addresses are disallowed
	tests := []struct {
		name  string
		ipStr string
		want  *net.IPAddr
	}{
		{
			name:  "Empty zone",
			ipStr: "1.1.1.1%",
			want:  &net.IPAddr{IP: net.ParseIP("1.1.1.1"), Zone: ""},
		},
		{
			name:  "No zone",
			ipStr: "1.1.1.1",
			want:  &net.IPAddr{IP: net.ParseIP("1.1.1.1"), Zone: ""},
		},
		{
			name:  "With zone",
			ipStr: "fe80::abcd%zone",
			want:  &net.IPAddr{IP: net.ParseIP("fe80::abcd"), Zone: "zone"},
		},
		{
			name:  "With zone and port",
			ipStr: "[2001:db8:cafe::17%zone]:4484",
			want:  &net.IPAddr{IP: net.ParseIP("2001:db8:cafe::17"), Zone: "zone"},
		},
		{
			name:  "With port",
			ipStr: "1.1.1.1:48944",
			want:  &net.IPAddr{IP: net.ParseIP("1.1.1.1"), Zone: ""},
		},
		{
			name:  "Bad port (is discarded)",
			ipStr: "[fe80::abcd%eth0]:xyz",
			want:  &net.IPAddr{IP: net.ParseIP("fe80::abcd"), Zone: "eth0"},
		},
		{
			name:  "Error: Zero address",
			ipStr: "0.0.0.0",
			want:  nil,
		},
		{
			name:  "Error: Unspecified address",
			ipStr: "::",
			want:  nil,
		},
		{
			name:  "Error: bad IP with zone",
			ipStr: "nope%zone",
			want:  nil,
		},
		{
			name:  "Error: bad IP",
			ipStr: "nope!!",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := goodIPAddr(tt.ipStr)

			if got == nil || tt.want == nil {
				if got != tt.want {
					t.Fatalf("ParseIPAddr() = %v, want %v", got, tt.want)
				}
				return
			}

			if !ipAddrsEqual(*got, *tt.want) {
				t.Fatalf("ParseIPAddr() = %v, want %v", *got, *tt.want)
			}
		})
	}
}

func Test_isPrivateOrLocal(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{
			name: "IPv4 loopback",
			ip:   `127.0.0.2`,
			want: true,
		},
		{
			name: "IPv6 loopback",
			ip:   `::1`,
			want: true,
		},
		{
			name: "IPv4 10.*",
			ip:   `10.0.0.1`,
			want: true,
		},
		{
			name: "IPv4 192.168.*",
			ip:   `192.168.1.1`,
			want: true,
		},
		{
			name: "IPv6 unique local address",
			ip:   `fd12:3456:789a:1::1`,
			want: true,
		},
		{
			name: "IPv4 link-local",
			ip:   `169.254.1.1`,
			want: true,
		},
		{
			name: "IPv6 link-local",
			ip:   `fe80::abcd`,
			want: true,
		},
		{
			name: "Non-local IPv4",
			ip:   `1.1.1.1`,
			want: false,
		},
		{
			name: "Non-local IPv4-mapped IPv6",
			ip:   `::ffff:188.0.2.128`,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("net.ParseIP failed; bad test input")
			}
			if got := isPrivateOrLocal(ip); got != tt.want {
				t.Fatalf("isPrivateOrLocal() = %v, want %v", got, tt.want)
			}
		})
	}
}
