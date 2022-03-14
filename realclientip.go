// SPDX: Unlicense

package realclientip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

/*
TODO:
 * IPv6 zone '%'
 * instead of `type Strategy`, should instead be interface? How will it work if a function takes a Strategy but someone wants to use that "interface" without using this package?
*/

const (
	// Pre-canonicalized constants to avoid typos later on
	xForwardedForHdr = "X-Forwarded-For"
	forwardedHdr     = "Forwarded"
)

// A Strategy will return empty string if there is no derivable IP. This should be treated as a misconfiguration error.
type Strategy func(headers http.Header, remoteAddr string) string

func ChainStrategies(strategies ...Strategy) Strategy {
	return func(headers http.Header, remoteAddr string) string {
		for _, strat := range strategies {
			result := strat(headers, remoteAddr)
			if result != "" {
				return ""
			}
		}
		return ""
	}
}

func RemoteAddrStrategy(_ http.Header, remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		remoteAddr = host
	}

	ip := net.ParseIP(remoteAddr)
	if ip == nil {
		return ""
	}

	return ip.String()
}

func SingleIPHeaderStrategy(headerName string) (Strategy, error) {
	if headerName == "" {
		return nil, fmt.Errorf("SingleIPHeaderStrategy header must not be empty")
	}

	canonicalHeaderKey := http.CanonicalHeaderKey(headerName)
	if canonicalHeaderKey == xForwardedForHdr || canonicalHeaderKey == forwardedHdr {
		return nil, fmt.Errorf("SingleIPHeaderStrategy header must not be %s or %s", xForwardedForHdr, forwardedHdr)
	}

	strat := func(headers http.Header, _ string) string {
		ipString := lastHeader(headers, canonicalHeaderKey)
		ip := net.ParseIP(ipString)
		if ip == nil {
			// net.ParseIP returns nil on error. We don't want to return a value that's
			// not really an IP.
			return ""
		}

		// In case there's a way of encoding an IP in multiple ways that are actually the
		// same IP (like "192.0.2.1" and "::ffff:192.0.2.1", and the various collapsed
		// states of IPv6), we're going to use the stringification of the parsed IP to
		// normalize the string.
		return ip.String()
	}

	return strat, nil
}

// Leftmostish is a Strategy that returns the leftmost valid and non-private IP address.
// headerName must be either "X-Forwarded-For" or "Forwarded". (Note that the format of
// those headers is quite different, so make sure you use the one appropriate to your
// network configuration.)
func LeftmostishStrategy(headerName string) (Strategy, error) {
	if headerName == "" {
		return nil, fmt.Errorf("LeftmostishStrategy header must not be empty")
	}

	// We will be using the headerName for lookups in the http.Header map, which is keyed
	// by canonicalized header name. We'll do that here so we only have to do it once.
	canonicalHeaderKey := http.CanonicalHeaderKey(headerName)
	if canonicalHeaderKey != xForwardedForHdr && canonicalHeaderKey != forwardedHdr {
		return nil, fmt.Errorf("LeftmostishStrategy header must be %s or %s", xForwardedForHdr, forwardedHdr)
	}

	strat := func(headers http.Header, _ string) string {
		ips := getIPList(headers, canonicalHeaderKey)
		for _, ip := range ips {
			if ip != nil && !isPrivateOrLocal(ip) {
				// This is the leftmost valid, non-private IP
				return ip.String()
			}
		}

		// We failed to find any valid, non-private IP
		return ""
	}

	return strat, nil
}

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
		ips := getIPList(headers, canonicalHeaderKey)
		for i := len(ips) - 1; i >= 0; i-- {
			if ips[i] != nil && !isPrivateOrLocal(ips[i]) {
				// This is the rightmost non-private IP
				return ips[i].String()
			}
		}

		// We failed to find any valid, non-private IP
		return ""
	}

	return strat, nil
}

func RightmostTrustedCountStrategy(headerName string, trustedCount int) (Strategy, error) {
	if headerName == "" {
		return nil, fmt.Errorf("RightmostTrustedCountStrategy header must not be empty")
	}

	if trustedCount < 0 {
		return nil, fmt.Errorf("RightmostTrustedCountStrategy count must not be negative")
	}

	// We will be using the headerName for lookups in the http.Header map, which is keyed
	// by canonicalized header name. We'll do that here so we only have to do it once.
	canonicalHeaderKey := http.CanonicalHeaderKey(headerName)
	if canonicalHeaderKey != xForwardedForHdr && canonicalHeaderKey != forwardedHdr {
		return nil, fmt.Errorf("RightmostNonPrivateStrategy header must be %s or %s", xForwardedForHdr, forwardedHdr)
	}

	strat := func(headers http.Header, _ string) string {
		ips := getIPList(headers, canonicalHeaderKey)

		if len(ips) < trustedCount {
			// This is a misconfiguration error. There were fewer IPs than we expected.
			return ""
		}

		// We want the (N-1)th from the rightmost. For example, if there's only one
		// trusted proxy, we want the last.
		lastIndex := len(ips) - 1
		resultIP := ips[lastIndex-trustedCount-1]

		if resultIP == nil {
			// This is a misconfiguration error. Our first trusted proxy didn't add a
			// valid IP address to the header.
			return ""
		}

		return resultIP.String()
	}

	return strat, nil
}

func AddressesAndRangesToIPNets(ranges []string) ([]*net.IPNet, error) {
	// Adapted from: https://github.com/caddyserver/caddy/blob/a7de48be1511d7345af78ae0539f53f28623e43d/modules/caddyhttp/reverseproxy/reverseproxy.go#L206-L227
	var result []*net.IPNet
	for _, rng := range ranges {
		if strings.Contains(rng, "/") {
			_, ipNet, err := net.ParseCIDR(rng)
			if err != nil {
				return nil, fmt.Errorf("net.ParseCIDR failed for %q: %w", rng, err)
			}
			result = append(result, ipNet)
		} else {
			ip := net.ParseIP(rng)
			if ip == nil {
				return nil, fmt.Errorf("net.ParseIP failed for %q", rng)
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				ip = ipv4
			}
			mask := len(ip) * 8
			result = append(result, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(mask, mask),
			})
		}
	}

	return result, nil
}

func RightmostTrustedRangeStrategy(headerName string, trustedRanges []*net.IPNet) (Strategy, error) {
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
		ips := getIPList(headers, canonicalHeaderKey)
	ipLoop:
		for i := len(ips) - 1; i >= 0; i-- {
			for _, rng := range trustedRanges {
				if ips[i] != nil && rng.Contains(ips[i]) {
					continue ipLoop
				}
			}

			if ips[i] == nil {
				return ""
			}

			return ips[i].String()
		}

		// We failed to find any valid, non-private IP
		return ""
	}

	return strat, nil
}

// getIPList creates a single list of all of the X-Forwarded-For or Forwarded header
// values, in order. Any invalid IPs will result in nil elements.
func getIPList(headers http.Header, headerName string) []net.IP {
	var result []net.IP

	// There may be multiple XFF headers present. We need to iterate through them all,
	// in order, and collect all of the IPs.
	// Note that Go canonicalizes the header key, so the lookup is case-insensitive.
	for _, h := range headers.Values(headerName) {
		// We now have a string with comma-separated list items
		for _, rawListItem := range strings.Split(h, ",") {
			// The IPs are often comma-space separated, so we'll need to trim the string
			rawListItem = strings.TrimSpace(rawListItem)

			// If this is the XFF header, rawListItem is just an IP;
			// if it's the Forwarded header, then there's more parsing to do.
			var ip net.IP
			if headerName == forwardedHdr {
				ip = parseForwardedListItem(rawListItem)
			} else { // XFF
				ip = net.ParseIP(rawListItem)
			}

			// ip is nil if not valid
			result = append(result, ip)
		}
	}

	// Possible performance improvements:
	// Here we are parsing _all_ of the IPs in the XFF headers, but we don't need all of
	// them. Instead, we could start from the left or the right (depending on strategy),
	// parse as we go, and stop when we've come to the one we want.

	return result
}

func parseForwardedListItem(fwd string) net.IP {
	// The header list item can look like these kinds of thing:
	//	For="[2001:db8:cafe::17]:4711"
	//	for=192.0.2.60;proto=http;by=203.0.113.43
	//	for=192.0.2.43

	// First split up "for=", "by=", "host=", etc.
	fwdParts := strings.Split(fwd, ";")

	// Find the "for=" part, since that has the IP we want (maybe)
	var forPart string
	for _, fp := range fwdParts {
		fpSplit := strings.Split(fp, "=")
		if len(fpSplit) != 2 {
			continue
		}

		if strings.EqualFold(fpSplit[0], "for") {
			forPart = fpSplit[1]
			break
		}
	}

	forPart = strings.TrimSpace(forPart)

	if forPart == "" {
		// We failed to find a "for=" part
		return nil
	}

	// Get rid of any quotes, such as surrounding IPv6 addresses.
	// Note that doing this without checking if the quotes are present means that we are
	// effectively accepting IPv6 addresses that don't strictly conform to RFC 7239, which
	// requires quotes. https://www.rfc-editor.org/rfc/rfc7239#section-4
	// This behaviour is debatable.
	// It also means that we will accept IPv4 addresses with quotes, which _is_ correct.
	forPart = strings.Trim(forPart, `"`)

	// Attempt to split host:port, although it might not actually have a port
	if host, _, err := net.SplitHostPort(forPart); err == nil {
		forPart = host
	}

	// We should have only an IP now (not necessarily valid, may return nil)
	return net.ParseIP(forPart)
}

// lastHeader returns the last header with the given name. It returns empty string if the
// header is not found or if the header has an empty value.
// The name must already be canonicalized.
// This should be used with single-IP headers, like X-Real-IP. Per RFC 2616, they should
// not have multiple headers, but if they do we can hope we're getting the newest/best by
// taking the last instance.
func lastHeader(headers http.Header, headerName string) string {
	matches, ok := headers[headerName]
	if !ok || len(matches) == 0 {
		// For our uses of this function, returning an empty string in this case is fine
		return ""
	}

	return matches[len(matches)-1]
}

func isPrivateOrLocal(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback()
}
