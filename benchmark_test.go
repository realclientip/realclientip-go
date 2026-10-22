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
// benchmarks and the allocs guards below exercise that property against a deliberately
// comma-stuffed header.

// makeStuffedHeader builds an X-Forwarded-For or Forwarded header with itemCount items. If
// targetAtEnd is true the lone "interesting" IP (a public, untrusted address) is the
// rightmost item and every other item is a private filler; otherwise it is the leftmost.
// Putting the target at the near end lets a strategy find its answer on the first item it
// inspects, so a benchmark measures the lazy path rather than the answer-finding logic.
// Putting it at the far end gives the strategy's worst case.
func makeStuffedHeader(headerName string, itemCount int, targetAtEnd bool) http.Header {
	// filler is private; target is a genuinely public, non-special-use address (note that
	// the RFC 5737 documentation ranges like 203.0.113.0/24 are special-use and would be
	// rejected by the non-private strategies, so we must not use them here).
	filler, target := "10.0.0.1", "8.8.8.8"
	if headerName == forwardedHdr {
		filler, target = "for="+filler, "for="+target
	}

	items := make([]string, itemCount)
	for i := range items {
		items[i] = filler
	}
	if targetAtEnd {
		items[len(items)-1] = target
	} else {
		items[0] = target
	}

	return http.Header{headerName: []string{strings.Join(items, ", ")}}
}

func BenchmarkRightmostNonPrivate_StuffedHeader(b *testing.B) {
	strat := Must(NewRightmostNonPrivateStrategy("X-Forwarded-For"))
	headers := makeStuffedHeader(xForwardedForHdr, 10000, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strat.ClientIP(headers, "")
	}
}

func BenchmarkRightmostTrustedCount_StuffedHeader(b *testing.B) {
	strat := Must(NewRightmostTrustedCountStrategy("X-Forwarded-For", 1))
	headers := makeStuffedHeader(xForwardedForHdr, 10000, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strat.ClientIP(headers, "")
	}
}

func BenchmarkRightmostTrustedRange_StuffedHeader(b *testing.B) {
	// No trusted ranges, so the rightmost item is immediately untrusted and returned.
	strat := Must(NewRightmostTrustedRangeStrategy("X-Forwarded-For", nil))
	headers := makeStuffedHeader(xForwardedForHdr, 10000, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strat.ClientIP(headers, "")
	}
}

func BenchmarkLeftmostNonPrivate_StuffedHeader(b *testing.B) {
	strat := Must(NewLeftmostNonPrivateStrategy("X-Forwarded-For"))
	headers := makeStuffedHeader(xForwardedForHdr, 10000, false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strat.ClientIP(headers, "")
	}
}

// BenchmarkLeftmostNonPrivate_StuffedHeaderWorstCase puts the target at the far (right)
// end, so the walk parses every private filler item before reaching it. The client controls
// everything left of its own IP, so LeftmostNonPrivateStrategy can't avoid this, and the
// cost here is proportional to the item count. This benchmark makes that cost visible; it
// is not a regression guard.
func BenchmarkLeftmostNonPrivate_StuffedHeaderWorstCase(b *testing.B) {
	strat := Must(NewLeftmostNonPrivateStrategy("X-Forwarded-For"))
	headers := makeStuffedHeader(xForwardedForHdr, 10000, true)

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
	strategies := []struct {
		name        string
		newStrat    func(headerName string) Strategy
		targetAtEnd bool
	}{
		{
			name:        "RightmostNonPrivate",
			newStrat:    func(h string) Strategy { return Must(NewRightmostNonPrivateStrategy(h)) },
			targetAtEnd: true,
		},
		{
			name:        "RightmostTrustedCount",
			newStrat:    func(h string) Strategy { return Must(NewRightmostTrustedCountStrategy(h, 1)) },
			targetAtEnd: true,
		},
		{
			name:        "RightmostTrustedRange",
			newStrat:    func(h string) Strategy { return Must(NewRightmostTrustedRangeStrategy(h, nil)) },
			targetAtEnd: true,
		},
		{
			// Only LeftmostNonPrivateStrategy's best case is lazy; its worst case is
			// proportional to the item count by necessity. See
			// BenchmarkLeftmostNonPrivate_StuffedHeaderWorstCase.
			name:        "LeftmostNonPrivate",
			newStrat:    func(h string) Strategy { return Must(NewLeftmostNonPrivateStrategy(h)) },
			targetAtEnd: false,
		},
	}

	for _, headerName := range []string{xForwardedForHdr, forwardedHdr} {
		for _, s := range strategies {
			t.Run(headerName+"/"+s.name, func(t *testing.T) {
				strat := s.newStrat(headerName)
				small := makeStuffedHeader(headerName, 10, s.targetAtEnd)
				large := makeStuffedHeader(headerName, 10000, s.targetAtEnd)

				allocsSmall := testing.AllocsPerRun(100, func() {
					_ = strat.ClientIP(small, "")
				})
				allocsLarge := testing.AllocsPerRun(100, func() {
					_ = strat.ClientIP(large, "")
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
}

// TestRightmostTrustedCountSkipsWithoutParsing checks that RightmostTrustedCountStrategy
// does not parse the items it skips on the way to its target. TestStrategiesAreLazy can't
// catch that: the strategy skips trustedCount-1 items whatever the header size. So here the
// header stays fixed and trustedCount grows instead. Both targets are the same filler item,
// and the target is the only item that should be parsed, so the allocation count must not
// grow with trustedCount.
func TestRightmostTrustedCountSkipsWithoutParsing(t *testing.T) {
	for _, headerName := range []string{xForwardedForHdr, forwardedHdr} {
		t.Run(headerName, func(t *testing.T) {
			headers := makeStuffedHeader(headerName, 10000, true)
			allocs := func(trustedCount int) float64 {
				strat := Must(NewRightmostTrustedCountStrategy(headerName, trustedCount))
				return testing.AllocsPerRun(100, func() {
					_ = strat.ClientIP(headers, "")
				})
			}

			allocsNear, allocsFar := allocs(2), allocs(1000)
			if allocsFar > allocsNear {
				t.Errorf("allocations grew with trustedCount: 2 -> %v allocs/op, 1000 -> %v allocs/op; "+
					"the strategy appears to be parsing the items it skips",
					allocsNear, allocsFar)
			}
		})
	}
}
