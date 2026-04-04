package scanner

import (
	"context"
	"iter"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type nameCache interface {
	LookupName(ip string) (string, bool)
	StoreName(ip, name string)
}

type icmpProber interface {
	Probe(ctx context.Context, ip string, timeout time.Duration) (bool, time.Duration, error)
	Warm(ip string) error
	Close() error
}

type ouiLoader interface {
	LoadOUICSV() error
}

type icmpFactory interface {
	NewICMPScanner() (icmpProber, error)
}

type passiveMDNSListener interface {
	Start(context.Context) nameCache
}

type activeARPSweeper interface {
	Start(context.Context, string, *ARPCache)
}

type targetExpander interface {
	Expand(string) (targetSpec, error)
}

type subnetPreheater interface {
	Preheat(context.Context, iter.Seq[string], int, icmpProber)
}

type hostDiscoverer interface {
	Discover(context.Context, models.ScanOptions, func(done, total int), nameCache, icmpProber, *ARPCache, *socketLimiter) <-chan HostEvent
}

type portScanner interface {
	Scan(context.Context, *models.Host, models.ScanOptions, chan struct{}, *socketLimiter)
}

type hostEnricher interface {
	Enrich(*models.Host, nameCache, *ARPCache)
}

type osDetector interface {
	Detect(string, []models.Port, time.Duration) (string, string)
}

type engineDependencies struct {
	ouiLoader           ouiLoader
	icmpFactory         icmpFactory
	passiveMDNSListener passiveMDNSListener
	activeARPSweeper    activeARPSweeper
	targetExpander      targetExpander
	subnetPreheater     subnetPreheater
	hostDiscoverer      hostDiscoverer
	portScanner         portScanner
	hostEnricher        hostEnricher
	osDetector          osDetector
}

type ouiLoaderFunc func() error

func (f ouiLoaderFunc) LoadOUICSV() error {
	return f()
}

type icmpFactoryFunc func() (icmpProber, error)

func (f icmpFactoryFunc) NewICMPScanner() (icmpProber, error) {
	return f()
}

type passiveMDNSListenerFunc func(context.Context) nameCache

func (f passiveMDNSListenerFunc) Start(ctx context.Context) nameCache {
	return f(ctx)
}

type activeARPSweeperFunc func(context.Context, string, *ARPCache)

func (f activeARPSweeperFunc) Start(ctx context.Context, target string, cache *ARPCache) {
	f(ctx, target, cache)
}

type targetExpanderFunc func(string) (targetSpec, error)

func (f targetExpanderFunc) Expand(target string) (targetSpec, error) {
	return f(target)
}

type subnetPreheaterFunc func(context.Context, iter.Seq[string], int, icmpProber)

func (f subnetPreheaterFunc) Preheat(ctx context.Context, ips iter.Seq[string], total int, icmp icmpProber) {
	f(ctx, ips, total, icmp)
}

type hostDiscovererFunc func(context.Context, models.ScanOptions, func(done, total int), nameCache, icmpProber, *ARPCache, *socketLimiter) <-chan HostEvent

func (f hostDiscovererFunc) Discover(
	ctx context.Context,
	opts models.ScanOptions,
	progress func(done, total int),
	cache nameCache,
	icmp icmpProber,
	arpCache *ARPCache,
	socketLimiter *socketLimiter,
) <-chan HostEvent {
	return f(ctx, opts, progress, cache, icmp, arpCache, socketLimiter)
}

type portScannerFunc func(context.Context, *models.Host, models.ScanOptions, chan struct{}, *socketLimiter)

func (f portScannerFunc) Scan(
	ctx context.Context,
	host *models.Host,
	opts models.ScanOptions,
	sem chan struct{},
	socketLimiter *socketLimiter,
) {
	f(ctx, host, opts, sem, socketLimiter)
}

type hostEnricherFunc func(*models.Host, nameCache, *ARPCache)

func (f hostEnricherFunc) Enrich(host *models.Host, cache nameCache, arp *ARPCache) {
	f(host, cache, arp)
}

type osDetectorFunc func(string, []models.Port, time.Duration) (string, string)

func (f osDetectorFunc) Detect(ip string, ports []models.Port, timeout time.Duration) (string, string) {
	return f(ip, ports, timeout)
}

var (
	_ nameCache  = (*mdnsCache)(nil)
	_ icmpProber = (*ICMPScanner)(nil)
)
