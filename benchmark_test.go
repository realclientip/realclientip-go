// SPDX: 0BSD

package realclientip

import (
	"net/http"
	"strings"
	"testing"
)

// The header item count is attacker-controlled: a client can send an X-Forwarded-For or
// Forwarded header packed with tens of thousands of comma-separated entries (bounded only
// by http.Server.MaxHeaderBytes). The strategies must therefore do work proportional to the
// number of items they actually inspect, not to the number of items in the header. These
// benchmarks and the allocs guard below exercise that property against a deliberately
// comma-stuffed header.

// makeStuffedXFF builds an X-Forwarded-For value with itemCount items. If targetAtEnd is
// true the lone "interesting" IP (a public, untrusted address) is the rightmost item and
// every other item is a private filler; otherwise it is the leftmost. This lets a rightmost
// strategy find its answer on the first item it inspects (and a leftmost strategy likewise),
// so the benchmark measures the lazy path rather than the answer-finding logic.
func makeStuffedXFF(itemCount int, targetAtEnd bool) http.Header {
	// filler is private; target is a genuinely public, non-special-use address (note that
	// the RFC 5737 documentation ranges like 203.0.113.0/24 are special-use and would be
	// rejected by the non-private strategies, so we must not use them here).
	const filler = "10.0.0.1"
	const target = "8.8.8.8"

	items := make([]string, itemCount)
	for i := range items {
		items[i] = filler
	}
	if targetAtEnd {
		items[len(items)-1] = target
	} else {
		items[0] = target
	}

	return http.Header{"X-Forwarded-For": []string{strings.Join(items, ", ")}}
}

func BenchmarkRightmostNonPrivate_StuffedHeader(b *testing.B) {
	strat := Must(NewRightmostNonPrivateStrategy("X-Forwarded-For"))
	headers := makeStuffedXFF(10000, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strat.ClientIP(headers, "")
	}
}

func BenchmarkRightmostTrustedCount_StuffedHeader(b *testing.B) {
	strat := Must(NewRightmostTrustedCountStrategy("X-Forwarded-For", 1))
	headers := makeStuffedXFF(10000, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strat.ClientIP(headers, "")
	}
}

func BenchmarkRightmostTrustedRange_StuffedHeader(b *testing.B) {
	// No trusted ranges, so the rightmost item is immediately untrusted and returned.
	strat := Must(NewRightmostTrustedRangeStrategy("X-Forwarded-For", nil))
	headers := makeStuffedXFF(10000, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strat.ClientIP(headers, "")
	}
}

func BenchmarkLeftmostNonPrivate_StuffedHeader(b *testing.B) {
	strat := Must(NewLeftmostNonPrivateStrategy("X-Forwarded-For"))
	headers := makeStuffedXFF(10000, false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strat.ClientIP(headers, "")
	}
}

// TestStrategiesAreLazy is a regression guard for the whole point of the lazy walk: a
// strategy that finds its answer at the near end of the header must do the same amount of
// work whether the header has a handful of items or tens of thousands. We assert that the
// per-call allocation count does not grow with the item count. If someone reintroduces an
// eager split/parse-everything implementation, the large-header allocation count will jump
// and this test will fail.
func TestStrategiesAreLazy(t *testing.T) {
	tests := []struct {
		name        string
		strat       Strategy
		targetAtEnd bool
	}{
		{
			name:        "RightmostNonPrivate",
			strat:       Must(NewRightmostNonPrivateStrategy("X-Forwarded-For")),
			targetAtEnd: true,
		},
		{
			name:        "RightmostTrustedCount",
			strat:       Must(NewRightmostTrustedCountStrategy("X-Forwarded-For", 1)),
			targetAtEnd: true,
		},
		{
			name:        "RightmostTrustedRange",
			strat:       Must(NewRightmostTrustedRangeStrategy("X-Forwarded-For", nil)),
			targetAtEnd: true,
		},
		{
			name:        "LeftmostNonPrivate",
			strat:       Must(NewLeftmostNonPrivateStrategy("X-Forwarded-For")),
			targetAtEnd: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			small := makeStuffedXFF(10, tt.targetAtEnd)
			large := makeStuffedXFF(10000, tt.targetAtEnd)

			allocsSmall := testing.AllocsPerRun(100, func() {
				_ = tt.strat.ClientIP(small, "")
			})
			allocsLarge := testing.AllocsPerRun(100, func() {
				_ = tt.strat.ClientIP(large, "")
			})

			// The work is identical regardless of item count, so the allocation counts
			// should match. Allow no growth with the 1000x larger header.
			if allocsLarge > allocsSmall {
				t.Errorf("allocations grew with header size: %v items -> %v allocs/op, %v items -> %v allocs/op; "+
					"the strategy appears to be doing work proportional to the number of items",
					10, allocsSmall, 10000, allocsLarge)
			}
		})
	}
}
