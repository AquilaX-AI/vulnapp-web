package main

import (
	"sync"
	"time"
)

// detectHighFrequencyScanning tracks recent request timestamps per client
// IP and flags unusually fast/broad crawling as likely automated
// scanning, even when no single request's content matches a known
// payload signature - catching careful scanners that avoid obvious
// patterns but still crawl far faster or more exhaustively than any
// human clicking through a site.
const (
	rateWindow    = 5 * time.Second
	rateThreshold = 20 // requests from the same IP within rateWindow
)

var (
	rateMu      sync.Mutex
	rateHistory = map[string][]time.Time{}
)

func detectHighFrequencyScanning(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-rateWindow)

	rateMu.Lock()
	defer rateMu.Unlock()

	kept := rateHistory[ip][:0]
	for _, t := range rateHistory[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	rateHistory[ip] = kept

	return len(kept) > rateThreshold
}

// startRateDetectCleanup periodically drops IPs with no recent activity
// so rateHistory doesn't grow without bound over a long-running process.
func startRateDetectCleanup() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			cutoff := time.Now().Add(-10 * time.Minute)
			rateMu.Lock()
			for ip, history := range rateHistory {
				if len(history) == 0 || history[len(history)-1].Before(cutoff) {
					delete(rateHistory, ip)
				}
			}
			rateMu.Unlock()
		}
	}()
}
