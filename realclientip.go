// SPDX: Unlicense

package realclientip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

const (
	// Pre-canonicalized constants to avoid typos later on
	xForwardedForHdr = "X-Forwarded-For"
	forwardedHdr     = "Forwarded"
)

// A Strategy will return empty string if there is no derivable IP. In many cases this
// should be treated as a misconfiguration error, unless the strategy is attempting to get
// an untrustworthy or optional value.
type Strategy func(headers http.Header, remoteAddr string) string

// Must panics if err is not nil. This can be used to make sure the Strategy-making
// functions do not return an error. It can also facilitate calling ChainStrategies.
func Must(strat Strategy, err error) Strategy {
	if err != nil {
		panic(fmt.Sprintf("err is not nil: %v", err))
	}
	return strat
}

// ChainStrategies attempts to use the given strategies in order. If the first one returns
// an empty string, the second one is tried, and so on, until a good IP is found or the
// strategies are exhausted. The IP may contain a zone identifier.
// A common use for this is if a server is both directly connected to the internet and
// expecting a header to check. It might be called like:
//   ChainStrategies(Must(LeftmostNonPrivateStrategy("X-Forwarded-For")), RemoteAddrStrategy)
func ChainStrategies(strategies ...Strategy) Strategy {
	return func(headers http.Header, remoteAddr string) string {
		for _, strat := range strategies {
			result := strat(headers, remoteAddr)
			if result != "" {
				return result
			}
		}
		return ""
	}
}

// RemoteAddrStrategy returns the remoteAddr IP, stripped of port. The IP may contain a
// zone identifier.
// If the IP is invalid, empty string will be returned. (This should not happen if
// req.RemoteAddr is passed without modification.)
// This Strategy should be used if the server is directly connected to the internet.
func RemoteAddrStrategy(_ http.Header, remoteAddr string) string {
	ipAddr := goodIPAddr(remoteAddr)
	if ipAddr == nil {
		return ""
	}

	return ipAddr.String()
}

// SingleIPHeaderStrategy creates a Strategy for deriving an IP address from a single-IP
// header. The IP may contain a zone identifier.
// If the IP is invalid, the Strategy returns an empty string.
// A non-exhaustive list of such single-IP headers is:
// X-Real-IP, CF-Connecting-IP, True-Client-IP, Fastly-Client-IP, X-Azure-ClientIP, X-Azure-SocketIP.
// This Strategy should be used when the given header is added by a trusted reverse proxy.
// You must ensure that this header is not spoofable (as is possible with Akamai's use of
// True-Client-IP, Fastly's default use of Fastly-Client-IP, and Azure's X-Azure-ClientIP).
func SingleIPHeaderStrategy(headerName string) (Strategy, error) {
	if headerName == "" {
		return nil, fmt.Errorf("SingleIPHeaderStrategy header must not be empty")
	}

	// We will be using the headerName for lookups in the http.Header map, which is keyed
	// by canonicalized header name. We'll do that here so we only have to do it once.
	canonicalHeaderKey := http.CanonicalHeaderKey(headerName)
	if canonicalHeaderKey == xForwardedForHdr || canonicalHeaderKey == forwardedHdr {
		return nil, fmt.Errorf("SingleIPHeaderStrategy header must not be %s or %s", xForwardedForHdr, forwardedHdr)
	}

	strat := func(headers http.Header, _ string) string {
		// RFC 2616 does not allow multiple instances of single-IP headers (or any non-list header).
		// It is debatable whether it is better to treat multiple such headers as an error
		// (more correct) or simply pick one of them (more flexible). As we've already
		// told the user tom make sure the header is not spoofable, we're going to use the
		// last header instance if there are multiple. (Using the last is arbitrary, but
		// in theory it should be the newest value.)
		ipStr := lastHeader(headers, canonicalHeaderKey)
		if ipStr == "" {
			// There is no header
			return ""
		}

		ipAddr := goodIPAddr(ipStr)
		if ipAddr == nil {
			// The header value is invalid
			return ""
		}

		return ipAddr.String()
	}

	return strat, nil
}

// LeftmostNonPrivateStrategy creates a Strategy that returns the leftmost valid and
// non-private IP address. The IP may contain a zone identifier.
// headerName must be either "X-Forwarded-For" or "Forwarded". (Note that the format of
// those headers is quite different, so make sure you use the one appropriate to your
// network configuration.)
// If the IP is invalid, the Strategy returns an empty string.
// This Strategy should be used when a valid, non-private IP closest to the client is desired.
// Note that this MUST NOT BE USED FOR SECURITY PURPOSES. This IP can be TRIVIALLY SPOOFED.
func LeftmostNonPrivateStrategy(headerName string) (Strategy, error) {
	if headerName == "" {
		return nil, fmt.Errorf("LeftmostNonPrivateStrategy header must not be empty")
	}

	// We will be using the headerName for lookups in the http.Header map, which is keyed
	// by canonicalized header name. We'll do that here so we only have to do it once.
	canonicalHeaderKey := http.CanonicalHeaderKey(headerName)
	if canonicalHeaderKey != xForwardedForHdr && canonicalHeaderKey != forwardedHdr {
		return nil, fmt.Errorf("LeftmostNonPrivateStrategy header must be %s or %s", xForwardedForHdr, forwardedHdr)
	}

	strat := func(headers http.Header, _ string) string {
		ipAddrs := getIPAddrList(headers, canonicalHeaderKey)
		for _, ip := range ipAddrs {
			if ip != nil && !isPrivateOrLocal(ip.IP) {
				// This is the leftmost valid, non-private IP
				return ip.String()
			}
		}

		// We failed to find any valid, non-private IP
		return ""
	}

	return strat, nil
}

// RightmostNonPrivateStrategy creates a Strategy that returns the rightmost valid,
// non-private/non-internal IP address. The IP may contain a zone identifier.
// headerName must be either "X-Forwarded-For" or "Forwarded". (Note that the format of
// those headers is quite different, so make sure you use the one appropriate to your
// network configuration.)
// If the IP is invalid, the Strategy returns an empty string.
// This Strategy should be used when  all the reverse proxies between the internet and the
// server have private-space IP addresses.
func RightmostNonPrivateStrategy(headerName string) (Strategy, error) {
	if headerName == "" {
		return nil, fmt.Errorf("RightmostNonPrivateStrategy header must not be empty")
	}

	// We will be using the headerName for lookups in the http.Header map, which is keyed
	// by canonicalized header name. We'll do that here so we only have to do it once.
	canonicalHeaderKey := http.CanonicalHeaderKey(headerName)
	if canonicalHeaderKey != xForwardedForHdr && canonicalHeaderKey != forwardedHdr {
		return nil, fmt.Errorf("RightmostNonPrivateStrategy header must be %s or %s", xForwardedForHdr, forwardedHdr)
	}

	strat := func(headers http.Header, _ string) string {
		ipAddrs := getIPAddrList(headers, canonicalHeaderKey)
		// Look backwards through the list of IP addresses
		for i := len(ipAddrs) - 1; i >= 0; i-- {
			if ipAddrs[i] != nil && !isPrivateOrLocal(ipAddrs[i].IP) {
				// This is the rightmost non-private IP
				return ipAddrs[i].String()
			}
		}

		// We failed to find any valid, non-private IP
		return ""
	}

	return strat, nil
}

// RightmostTrustedCountStrategy creates a Strategy that returns the valid
// IP address added by the first trusted reverse proxy. trustedCount is the number of
// reverse proxies between the internet and the server. It must be greater than zero. The
// IP returned will be the (trustedCount-1)th from the right. For example, if there's only
// one trusted proxy, this strategy will return the last (rightmost) IP address.
// The IP may contain a zone identifier.
// headerName must be either "X-Forwarded-For" or "Forwarded". (Note that the format of
// those headers is quite different, so make sure you use the one appropriate to your
// network configuration.)
// If the IP is invalid, the Strategy returns an empty string.
// This Strategy should be used when there is a fixed number of reverse proxies between
// the internet and the server.
func RightmostTrustedCountStrategy(headerName string, trustedCount int) (Strategy, error) {
	if headerName == "" {
		return nil, fmt.Errorf("RightmostTrustedCountStrategy header must not be empty")
	}

	if trustedCount <= 0 {
		return nil, fmt.Errorf("RightmostTrustedCountStrategy count must be greater than zero")
	}

	// We will be using the headerName for lookups in the http.Header map, which is keyed
	// by canonicalized header name. We'll do that here so we only have to do it once.
	canonicalHeaderKey := http.CanonicalHeaderKey(headerName)
	if canonicalHeaderKey != xForwardedForHdr && canonicalHeaderKey != forwardedHdr {
		return nil, fmt.Errorf("RightmostNonPrivateStrategy header must be %s or %s", xForwardedForHdr, forwardedHdr)
	}

	strat := func(headers http.Header, _ string) string {
		ipAddrs := getIPAddrList(headers, canonicalHeaderKey)

		// We want the (N-1)th from the rightmost. For example, if there's only one
		// trusted proxy, we want the last.
		rightmostIndex := len(ipAddrs) - 1
		targetIndex := rightmostIndex - (trustedCount - 1)

		if targetIndex < 0 {
			// This is a misconfiguration error. There were fewer IPs than we expected.
			return ""
		}

		resultIP := ipAddrs[targetIndex]

		if resultIP == nil {
			// This is a misconfiguration error. Our first trusted proxy didn't add a
			// valid IP address to the header.
			return ""
		}

		return resultIP.String()
	}

	return strat, nil
}

// AddressesAndRangesToIPNets converts a slice of strings with IPv4 and IPv6 addresses and
// CIDR ranges (prefixes) to net.IPNet instances.
// If net.ParseCIDR or net.ParseIP fail, an error will be returned.
// Zones in addresses or ranges are not allowed and will result in an error. This is because:
// a) net.ParseCIDR will fail to parse a range with a zone, and
// b) netip.ParsePrefix will succeed but silently throw away the zone; then
// netip.Prefix.Contains will return false for any IP with a zone, causing confusion and bugs.
func AddressesAndRangesToIPNets(ranges ...string) ([]net.IPNet, error) {
	var result []net.IPNet
	for _, r := range ranges {
		if strings.Contains(r, "%") {
			return nil, fmt.Errorf("zones are not allowed: %q", r)
		}

		if strings.Contains(r, "/") {
			// This is a CIDR/prefix
			_, ipNet, err := net.ParseCIDR(r)
			if err != nil {
				return nil, fmt.Errorf("net.ParseCIDR failed for %q: %w", r, err)
			}
			result = append(result, *ipNet)
		} else {
			// This is a single IP; convert it to a range including only itself
			ip := net.ParseIP(r)
			if ip == nil {
				return nil, fmt.Errorf("net.ParseIP failed for %q", r)
			}

			// To use the right size IP and  mask, we need to know if the address is IPv4 or v6.
			// Attempt to convert it to IPv4 to find out.
			if ipv4 := ip.To4(); ipv4 != nil {
				ip = ipv4
			}

			// Mask all the bits
			mask := len(ip) * 8
			result = append(result, net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(mask, mask),
			})
		}
	}

	return result, nil
}

// RightmostTrustedRangeStrategy creates a Strategy that returns the rightmost valid IP
// address which is not in trustedRanges. The IP may contain a zone identifier.
// trustedRanges can be private/internal or external (for example, if a third-party reverse proxy is used).
// headerName must be either "X-Forwarded-For" or "Forwarded". (Note that the format of
// those headers is quite different, so make sure you use the one appropriate to your
// network configuration.)
// If the IP is invalid, the Strategy returns an empty string.
// This Strategy should be used when the IP ranges of the reverse proxies between the
// internet and the server are known.
// If a third-party WAF, CDN, etc., is used, you SHOULD use a method of verifying it that
// is stronger than checking its IP address. Failure to do so can result in scenarios like:
// You use AWS CloudFront in front of a server you host elsewhere. An attacker creates a
// CF distribution that points at your origin server. The attacker uses Lambda@Edge to
// spoof the Host and X-Forwarded-For headers. Now your "trusted" reverse proxy is no
// longer trustworthy.
func RightmostTrustedRangeStrategy(headerName string, trustedRanges []net.IPNet) (Strategy, error) {
	if headerName == "" {
		return nil, fmt.Errorf("RightmostTrustedRangeStrategy header must not be empty")
	}

	// We will be using the headerName for lookups in the http.Header map, which is keyed
	// by canonicalized header name. We'll do that here so we only have to do it once.
	canonicalHeaderKey := http.CanonicalHeaderKey(headerName)
	if canonicalHeaderKey != xForwardedForHdr && canonicalHeaderKey != forwardedHdr {
		return nil, fmt.Errorf("RightmostTrustedRangeStrategy header must be %s or %s", xForwardedForHdr, forwardedHdr)
	}

	strat := func(headers http.Header, _ string) string {
		ipAddrs := getIPAddrList(headers, canonicalHeaderKey)
		// Look backwards through the list of IP addresses
		for i := len(ipAddrs) - 1; i >= 0; i-- {
			if ipAddrs[i] != nil && isIPContainedInRanges(ipAddrs[i].IP, trustedRanges) {
				// This IP is trusted
				continue
			}

			// At this point we have found the first-from-the-rightmost untrusted IP

			if ipAddrs[i] == nil {
				return ""
			}

			return ipAddrs[i].String()
		}

		// Either there are no addresses or they are all in our trusted ranges
		return ""
	}

	return strat, nil
}

// lastHeader returns the last header with the given name. It returns empty string if the
// header is not found or if the header has an empty value. No validation is done on the
// IP string. headerName must already be canonicalized.
// This should be used with single-IP headers, like X-Real-IP. Per RFC 2616, they should
// not have multiple headers, but if they do we can hope we're getting the newest/best by
// taking the last instance.
// This MUST NOT be used with list headers, like X-Forwarded-For and Forwarded.
func lastHeader(headers http.Header, headerName string) string {
	// Note that Go's Header map uses canonicalized keys
	matches, ok := headers[headerName]
	if !ok || len(matches) == 0 {
		// For our uses of this function, returning an empty string in this case is fine
		return ""
	}

	return matches[len(matches)-1]
}

// getIPAddrList creates a single list of all of the X-Forwarded-For or Forwarded header
// values, in order. Any invalid IPs will result in nil elements. headerName must already
// be canonicalized.
func getIPAddrList(headers http.Header, headerName string) []*net.IPAddr {
	var result []*net.IPAddr

	// There may be multiple XFF headers present. We need to iterate through them all,
	// in order, and collect all of the IPs.
	// Note that Go's Header map uses canonicalized keys.
	for _, h := range headers[headerName] {
		// We now have a string with comma-separated list items
		for _, rawListItem := range strings.Split(h, ",") {
			// The IPs are often comma-space separated, so we'll need to trim the string
			rawListItem = strings.TrimSpace(rawListItem)

			var ipAddr *net.IPAddr
			// If this is the XFF header, rawListItem is just an IP;
			// if it's the Forwarded header, then there's more parsing to do.
			if headerName == forwardedHdr {
				ipAddr = parseForwardedListItem(rawListItem)
			} else { // == XFF
				ipAddr = goodIPAddr(rawListItem)
			}

			// ipAddr is nil if not valid
			result = append(result, ipAddr)
		}
	}

	// Possible performance improvements:
	// Here we are parsing _all_ of the IPs in the XFF headers, but we don't need all of
	// them. Instead, we could start from the left or the right (depending on strategy),
	// parse as we go, and stop when we've come to the one we want. But that would make
	// the various strategies somewhat more complex.

	return result
}

// parseForwardedListItem parses a Forwarded header list item, and returns the "for" IP
// address. Nil is returned if the "for" IP is absent or invalid.
func parseForwardedListItem(fwd string) *net.IPAddr {
	// The header list item can look like these kinds of thing:
	//	For="[2001:db8:cafe::17%zone]:4711"
	//	for=192.0.2.60;proto=http;by=203.0.113.43
	//	for=192.0.2.43

	// First split up "for=", "by=", "host=", etc.
	fwdParts := strings.Split(fwd, ";")

	// Find the "for=" part, since that has the IP we want (maybe)
	var forPart string
	for _, fp := range fwdParts {
		fpSplit := strings.Split(fp, "=")
		if len(fpSplit) != 2 {
			// There are too many or too few equal signs in this part
			continue
		}

		if strings.EqualFold(fpSplit[0], "for") {
			// We found the "for=" part
			forPart = fpSplit[1]
			break
		}
	}

	// There shouldn't (per RFC 7239) be spaces around the semicolon or equal sign. It might
	// be more correct to consider spaces an error, but we'll tolerate and trim them.
	forPart = strings.TrimSpace(forPart)

	// Get rid of any quotes, such as surrounding IPv6 addresses.
	// Note that doing this without checking if the quotes are present means that we are
	// effectively accepting IPv6 addresses that don't strictly conform to RFC 7239, which
	// requires quotes. https://www.rfc-editor.org/rfc/rfc7239#section-4
	// This behaviour is debatable.
	// It also means that we will accept IPv4 addresses with quotes, which _is_ correct.
	forPart = strings.Trim(forPart, `"`)

	if forPart == "" {
		// We failed to find a "for=" part
		return nil
	}

	ipAddr := goodIPAddr(forPart)
	if ipAddr == nil {
		// The IP extracted from the "for=" part isn't valid
		return nil
	}

	return ipAddr
}

// ParseIPAddr parses the given string into a net.IPAddr, which is a useful type for
// dealing with IPs have zones. The Go stdlib net package is lacking such a function.
// This will also discard any port number from the input.
func ParseIPAddr(ipStr string) (net.IPAddr, error) {
	host, _, err := net.SplitHostPort(ipStr)
	if err == nil {
		ipStr = host
	}
	// We continue even if net.SplitHostPort returned an error. This is because it may
	// complain that there are "too many colons" in an IPv6 address that has no brackets
	// and no port. net.ParseIP will be the final arbiter of validity.

	ipStr, zone := SplitHostZone(ipStr)

	res := net.IPAddr{
		IP:   net.ParseIP(ipStr),
		Zone: zone,
	}

	if res.IP == nil {
		return net.IPAddr{}, fmt.Errorf("net.ParseIP failed")
	}

	return res, nil
}

// MustParseIPAddr panics if ParseIPAddr fails.
func MustParseIPAddr(ipStr string) net.IPAddr {
	ipAddr, err := ParseIPAddr(ipStr)
	if err != nil {
		panic(fmt.Sprintf("ParseIPAddr failed: %v", err))
	}
	return ipAddr
}

// goodIPAddr wraps ParseIPAddr and adds a check for unspecified (like "::") and zero-value
// addresses (like "0.0.0.0"). These are nominally valid IPs (net.ParseIP will accept them),
// but they are undesirable for the purposes of this library.
// Note that this function should be the only use of ParseIPAddr in this library.
func goodIPAddr(ipStr string) *net.IPAddr {
	ipAddr, err := ParseIPAddr(ipStr)
	if err != nil {
		return nil
	}

	if ipAddr.IP.IsUnspecified() {
		return nil
	}

	return &ipAddr
}

// SplitHostZone splits a "host%zone" string into its components. If there is no zone,
// host is the original input and zone is empty.
func SplitHostZone(s string) (host, zone string) {
	// This is copied from an unexported function in the Go stdlib:
	// https://github.com/golang/go/blob/5c9b6e8e63e012513b1cb1a4a08ff23dec4137a1/src/net/ipsock.go#L219-L228

	// The IPv6 scoped addressing zone identifier starts after the last percent sign.
	if i := strings.LastIndexByte(s, '%'); i > 0 {
		host, zone = s[:i], s[i+1:]
	} else {
		host = s
	}
	return
}

// mustParseCIDR panics if net.ParseCIDR fails
func mustParseCIDR(s string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *ipNet
}

// privateAndLocalRanges net.IPNets that are loopback, private, link local, default unicast.
// Based on https://github.com/wader/filtertransport/blob/bdd9e61eee7804e94ceb927c896b59920345c6e4/filter.go#L36-L64
// which is based on https://github.com/letsencrypt/boulder/blob/master/bdns/dns.go
var privateAndLocalRanges = []net.IPNet{
	mustParseCIDR("10.0.0.0/8"),         // RFC1918
	mustParseCIDR("172.16.0.0/12"),      // private
	mustParseCIDR("192.168.0.0/16"),     // private
	mustParseCIDR("127.0.0.0/8"),        // RFC5735
	mustParseCIDR("0.0.0.0/8"),          // RFC1122 Section 3.2.1.3
	mustParseCIDR("169.254.0.0/16"),     // RFC3927
	mustParseCIDR("192.0.0.0/24"),       // RFC 5736
	mustParseCIDR("192.0.2.0/24"),       // RFC 5737
	mustParseCIDR("198.51.100.0/24"),    // Assigned as TEST-NET-2
	mustParseCIDR("203.0.113.0/24"),     // Assigned as TEST-NET-3
	mustParseCIDR("192.88.99.0/24"),     // RFC 3068
	mustParseCIDR("192.18.0.0/15"),      // RFC 2544
	mustParseCIDR("224.0.0.0/4"),        // RFC 3171
	mustParseCIDR("240.0.0.0/4"),        // RFC 1112
	mustParseCIDR("255.255.255.255/32"), // RFC 919 Section 7
	mustParseCIDR("100.64.0.0/10"),      // RFC 6598
	mustParseCIDR("::/128"),             // RFC 4291: Unspecified Address
	mustParseCIDR("::1/128"),            // RFC 4291: Loopback Address
	mustParseCIDR("100::/64"),           // RFC 6666: Discard Address Block
	mustParseCIDR("2001::/23"),          // RFC 2928: IETF Protocol Assignments
	mustParseCIDR("2001:2::/48"),        // RFC 5180: Benchmarking
	mustParseCIDR("2001:db8::/32"),      // RFC 3849: Documentation
	mustParseCIDR("2001::/32"),          // RFC 4380: TEREDO
	mustParseCIDR("fc00::/7"),           // RFC 4193: Unique-Local
	mustParseCIDR("fe80::/10"),          // RFC 4291: Section 2.5.6 Link-Scoped Unicast
	mustParseCIDR("ff00::/8"),           // RFC 4291: Section 2.7
	mustParseCIDR("2002::/16"),          // RFC 7526: 6to4 anycast prefix deprecated
}

// isIPContainedInRanges returns true if the given IP is contained in at least one of the given ranges
func isIPContainedInRanges(ip net.IP, ranges []net.IPNet) bool {
	for _, r := range ranges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivateOrLocal return true if the given IP address is private, local, or otherwise
// not suitable for an external client IP.
func isPrivateOrLocal(ip net.IP) bool {
	return isIPContainedInRanges(ip, privateAndLocalRanges)
}
