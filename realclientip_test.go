// SPDX: Unlicense

package realclientip

import (
	"net"
	"net/http"
	"testing"
)

func Test_parseForwardedListItem(t *testing.T) {
	tests := []struct {
		name string
		fwd  string
		want net.IP
	}{
		{
			// This is the correct form for IPv6 wit port
			name: "IPv6 with port and quotes",
			fwd:  `For="[2001:db8:cafe::17]:4711"`,
			want: net.ParseIP("2001:db8:cafe::17"),
		},
		{
			// This is the correct form for IP with no port
			name: "IPv6 with quotes, no brackets, and no port",
			fwd:  `for="2001:db8:cafe::17"`,
			want: net.ParseIP("2001:db8:cafe::17"),
		},
		{
			// This is not strictly correct, but it will succeed as we don't check for quotes
			name: "IPv6 with port and no quotes",
			fwd:  `For=[2001:db8:cafe::17]:4711`,
			want: net.ParseIP("2001:db8:cafe::17"),
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
			want: net.ParseIP("192.0.2.60"),
		},
		{
			name: "IPv4 with no port",
			fwd:  `for=192.0.2.60`,
			want: net.ParseIP("192.0.2.60"),
		},
		{
			name: "IPv4 with quotes",
			fwd:  `for="192.0.2.60"`,
			want: net.ParseIP("192.0.2.60"),
		},
		{
			name: "IPv4 with port and quotes",
			fwd:  `for="192.0.2.60:4823"`,
			want: net.ParseIP("192.0.2.60"),
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
			want: net.ParseIP("2.2.2.2"),
		},
		{
			name: "Multiple IPv6 directives",
			fwd:  `by=1::1;host=myhost;for=2::2;proto=https`,
			want: net.ParseIP("2::2"),
		},
		{
			name: "Multiple mixed directives",
			fwd:  `by=1::1;host=myhost;proto=https;for=2.2.2.2`,
			want: net.ParseIP("2.2.2.2"),
		},
		{
			name: "IPv4-mapped IPv6",
			fwd:  `for=64:ff9b::192.0.2.128`,
			want: net.ParseIP("64:ff9b::192.0.2.128"),
		},
		{
			name: "Error: garbage",
			fwd:  "ads\x00jkl&#*(383fdljk",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseForwardedListItem(tt.fwd); !got.Equal(tt.want) {
				t.Errorf("parseForwardedListItem() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoteAddrStrategy(t *testing.T) {
	type args struct {
		in0        http.Header
		remoteAddr string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "RemoteAddr IPv4 with port",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"1.1.1.1"}},
				remoteAddr: "2.2.2.2:1234",
			},
			want: "2.2.2.2",
		},
		{
			name: "RemoteAddr IPv4 with no port",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"1.1.1.1"}},
				remoteAddr: "2.2.2.2",
			},
			want: "2.2.2.2",
		},
		{
			name: "RemoteAddr IPv6 with port",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"2001:db8:cafe::17"}},
				remoteAddr: "[2001:db8:cafe::18]:3838",
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "RemoteAddr IPv6 with no port",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"2001:db8:cafe::17"}},
				remoteAddr: "2001:db8:cafe::18",
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "RemoteAddr with IPv4-mapped IPv6",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"2001:db8:cafe::17"}},
				remoteAddr: "[::ffff:172.21.0.6]:4747",
			},
			// It is okay that this converts to the IPv4 format, since it's most important
			// that the respresentation be consistent. It might also be good that it does,
			// so that it will match the same plain IPv4 address.
			// net/netip.ParseAddr gives a different form: "::ffff:172.21.0.6"
			want: "172.21.0.6",
		},
		{
			name: "RemoteAddr with IPv4-mapped IPv6 in IPv6 form",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"2001:db8:cafe::17"}},
				remoteAddr: "0:0:0:0:0:ffff:ac15:0006",
			},
			// net/netip.ParseAddr gives a different form: "::ffff:172.21.0.6"
			want: "172.21.0.6",
		},
		{
			name: "RemoteAddr with NAT64 IPv4-mapped IPv6",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"2001:db8:cafe::17"}},
				remoteAddr: "[64:ff9b::192.0.2.128]:4747",
			},
			// net.ParseIP and net/netip.ParseAddr convert to this. This is fine, as it is
			// done consistently.
			want: "64:ff9b::c000:280",
		},
		{
			name: "RemoteAddr IPv6 with zone",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"2001:db8:cafe::17"}},
				remoteAddr: "[2001:db8:cafe::18%zone]:48948",
			},
			want: "2001:db8:cafe::18",
		},
		{
			name: "Garbage header",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"ohno"}},
				remoteAddr: "2.2.2.2:1234",
			},
			want: "2.2.2.2",
		},
		{
			name: "Error: garbage RemoteAddr",
			args: args{
				in0:        http.Header{"X-Forwarded-For": []string{"1.1.1.1"}},
				remoteAddr: "ohno",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoteAddrStrategy(tt.args.in0, tt.args.remoteAddr); got != tt.want {
				t.Errorf("RemoteAddrStrategy() = %q, want %q", got, tt.want)
			}
		})
	}
}
