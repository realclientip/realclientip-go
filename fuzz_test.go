// SPDX: 0BSD

package realclientip

import (
	"net"
	"net/http"
	"testing"
)

// ============================================================================
// Fuzz targets
//
// These run as ordinary tests against their seed corpus during `go test`, and
// as active, coverage-guided fuzzing under `go test -fuzz=...` (the Fuzz GitHub
// Actions workflow runs them nightly). When the fuzzer finds a failing input it
// writes it to testdata/fuzz/<FuzzName>/; commit that file to turn the finding
// into a permanent regression seed.
// ============================================================================

// Fuzz_parseForwardedListItem exercises the Forwarded-header "for=" parser --
// the library's most involved hand-written parsing -- against arbitrary input.
// Callers feed this untrusted header data, so the contract under test is
// robustness: it must never panic and never take pathological time, whatever
// the input. (Go's fuzzer reports both panics and inputs that run too long.)
//
// There is deliberately no result oracle: re-deriving the "correct" parse would
// just reimplement the function. The one cheap invariant we do assert is the
// return contract -- a non-nil *net.IPAddr always carries a non-nil IP, never a
// half-parsed value.
func Fuzz_parseForwardedListItem(f *testing.F) {
	seeds := []string{
		`For="[2607:f8b0:4004:83f::200e]:4711"`, `fOR="[2607:f8b0:4004:83f::200e]"`,
		`for="2607:f8b0:4004:83f::200e"`, `FOR=[2607:f8b0:4004:83f::200e]`,
		`For=[2607:f8b0:4004:83f::200e]:4711`, `For="[fe80::abcd%zone]:4711"`,
		`For="fe80::abcd%zone"`, `FoR=192.0.2.60:4711`, `for=192.0.2.60`,
		`for="192.0.2.60"`, `for="192.0.2.60:4823"`, `for=192.0.2.999`,
		`for="2607:f8b0:4004:83f::999999"`, `for="_test"`, `for=`,
		`by=1.1.1.1; for=2.2.2.2;host=myhost; proto=https`,
		`by=1::1;host=myhost;for=2::2;proto=https`,
		`by=1::1;host=myhost;proto=https;for=2.2.2.2`,
		`for="[::ffff:188.0.2.128]"`, `for="[::ffff:188.0.2.128]:49428"`,
		`for="[0:0:0:0:0:ffff:bc15:0006]"`, `for="[64:ff9b::188.0.2.128]"`,
		`for=127.0.0.1`, `for="[::1]"`, `for="1.1.1.1`, `for="::1]"`,
		`for="[0:0:0:0:0:ffff:bc15:0006"]`, `for=1.1.1.\1`, `for= 1.1.1.1`,
		"ads\x00jkl&#*(383fdljk",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, fwd string) {
		if ipAddr := parseForwardedListItem(fwd); ipAddr != nil && ipAddr.IP == nil {
			t.Fatalf("parseForwardedListItem(%q) returned a non-nil *net.IPAddr with a nil IP", fwd)
		}
	})
}

// Fuzz_ClientIP_XFF feeds arbitrary X-Forwarded-For header values and arbitrary
// remoteAddr values through the XFF-based strategies and checks invariants that
// are independent of how the strategies compute their answer -- genuine oracles
// rather than a reimplementation of the walk:
//
//   - Any non-empty result is a valid IP that round-trips: re-parsing and
//     re-stringifying it yields the identical string (the library promises
//     normalized, canonical output).
//   - Feeding a non-empty result back in as the whole header, with the same
//     remoteAddr, yields the same result (idempotence of the full strategy).
//   - LeftmostNonPrivate / RightmostNonPrivate never return a private/local IP.
//   - RightmostTrustedRange never returns an IP inside a trusted range -- which
//     must hold whether the result came from the header or from the verified
//     peer (remoteAddr).
func Fuzz_ClientIP_XFF(f *testing.F) {
	seeds := []struct{ xff, remoteAddr string }{
		{"1.1.1.1", ""},
		{"1.1.1.1, 2.2.2.2", "10.0.0.1:80"},                // trusted peer
		{"10.0.0.1, 192.168.1.1, 3.3.3.3", "9.9.9.9:1234"}, // untrusted peer
		{"::1, 2607:f8b0:4004:83f::200e", "@"},             // Unix-socket peer
		{"  fe80::1%eth0 , 4.4.4.4 ", "[fe80::1%eth0]:9"},
		{"not-an-ip, 5.5.5.5", "ohno"}, // unparseable peer
		{"1.1.1.1,,2.2.2.2", "[2607:f8b0::1]:443"},
		{"::ffff:188.0.2.128", "192.168.1.1:5"},
		{"", "9.9.9.9"},
	}
	for _, s := range seeds {
		f.Add(s.xff, s.remoteAddr)
	}

	trustedRanges, err := AddressesAndRangesToIPNets("10.0.0.0/8", "192.168.0.0/16", "fc00::/7")
	if err != nil {
		f.Fatalf("AddressesAndRangesToIPNets failed: %v", err)
	}

	leftmost, err := NewLeftmostNonPrivateStrategy(xForwardedForHdr)
	if err != nil {
		f.Fatalf("NewLeftmostNonPrivateStrategy failed: %v", err)
	}
	rightmost, err := NewRightmostNonPrivateStrategy(xForwardedForHdr)
	if err != nil {
		f.Fatalf("NewRightmostNonPrivateStrategy failed: %v", err)
	}
	trusted, err := NewRightmostTrustedRangeStrategy(xForwardedForHdr, trustedRanges)
	if err != nil {
		f.Fatalf("NewRightmostTrustedRangeStrategy failed: %v", err)
	}

	// Each strategy paired with the post-condition its result must satisfy.
	cases := []struct {
		strat    Strategy
		postcond func(net.IP) bool
		condName string
	}{
		{leftmost, func(ip net.IP) bool { return !isPrivateOrLocal(ip) }, "non-private"},
		{rightmost, func(ip net.IP) bool { return !isPrivateOrLocal(ip) }, "non-private"},
		{trusted, func(ip net.IP) bool { return !isIPContainedInRanges(ip, trustedRanges) }, "outside-trusted-ranges"},
	}

	f.Fuzz(func(t *testing.T, xff, remoteAddr string) {
		for _, c := range cases {
			result := c.strat.ClientIP(http.Header{xForwardedForHdr: []string{xff}}, remoteAddr)
			if result == "" {
				continue
			}

			// Must be a valid, canonical IP.
			ipAddr, err := ParseIPAddr(result)
			if err != nil {
				t.Fatalf("%T returned unparseable %q from XFF %q remoteAddr %q", c.strat, result, xff, remoteAddr)
			}
			if ipAddr.String() != result {
				t.Fatalf("%T result %q is not canonical (re-stringifies to %q)", c.strat, result, ipAddr.String())
			}

			// Post-condition for this strategy. For RightmostTrustedRange this also
			// covers the peer path: whether the result comes from remoteAddr or from
			// the header, it must still be outside the trusted ranges.
			if !c.postcond(ipAddr.IP) {
				t.Fatalf("%T result %q violates %s (XFF %q remoteAddr %q)", c.strat, result, c.condName, xff, remoteAddr)
			}

			// Idempotence: feeding the result back as the whole header, with the same
			// remoteAddr, yields it.
			back := c.strat.ClientIP(http.Header{xForwardedForHdr: []string{result}}, remoteAddr)
			if back != result {
				t.Fatalf("%T not idempotent: %q -> %q (remoteAddr %q)", c.strat, result, back, remoteAddr)
			}
		}
	})
}
