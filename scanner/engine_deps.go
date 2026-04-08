package scanner

import (
	"context"
	"iter"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

type nameCache interface {
	LookupName(ip string) (resolveResult, bool)
	StoreName(ip, name string, source models.HostSource)
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
	Start(context.Context) (passiveMDNSSession, error)
}

type passiveMDNSSession struct {
	cache        nameCache
	observations <-chan contracts.HostObservation
}

type activeARPSweeper interface {
	Start(context.Context, string, *ARPCache, issueReporter)
}

type targetExpander interface {
	Expand(string) (targetSpec, error)
}

type subnetPreheater interface {
	Preheat(context.Context, iter.Seq[string], int, icmpProber)
}

type hostDiscoverer interface {
	Discover(context.Context, models.ScanOptions, func(done, total int), nameCache, icmpProber, *ARPCache, contracts.DiscoveryRuntime) <-chan contracts.HostObservation
}

type portScanner interface {
	Scan(context.Context, *models.Host, models.ScanOptions, contracts.Runtime)
}

type hostEnricher interface {
	Enrich(*models.Host, *ARPCache)
}

type osDetector interface {
	Detect([]models.Port) (string, string)
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

type passiveMDNSListenerFunc func(context.Context) (passiveMDNSSession, error)

func (f passiveMDNSListenerFunc) Start(ctx context.Context) (passiveMDNSSession, error) {
	return f(ctx)
}

type activeARPSweeperFunc func(context.Context, string, *ARPCache, issueReporter)

func (f activeARPSweeperFunc) Start(ctx context.Context, target string, cache *ARPCache, issues issueReporter) {
	f(ctx, target, cache, issues)
}

type targetExpanderFunc func(string) (targetSpec, error)

func (f targetExpanderFunc) Expand(target string) (targetSpec, error) {
	return f(target)
}

type subnetPreheaterFunc func(context.Context, iter.Seq[string], int, icmpProber)

func (f subnetPreheaterFunc) Preheat(ctx context.Context, ips iter.Seq[string], total int, icmp icmpProber) {
	f(ctx, ips, total, icmp)
}

type hostDiscovererFunc func(context.Context, models.ScanOptions, func(done, total int), nameCache, icmpProber, *ARPCache, contracts.DiscoveryRuntime) <-chan contracts.HostObservation

func (f hostDiscovererFunc) Discover(
	ctx context.Context,
	opts models.ScanOptions,
	progress func(done, total int),
	cache nameCache,
	icmp icmpProber,
	arpCache *ARPCache,
	runtime contracts.DiscoveryRuntime,
) <-chan contracts.HostObservation {
	return f(ctx, opts, progress, cache, icmp, arpCache, runtime)
}

type portScannerFunc func(context.Context, *models.Host, models.ScanOptions, contracts.Runtime)

func (f portScannerFunc) Scan(
	ctx context.Context,
	host *models.Host,
	opts models.ScanOptions,
	runtime contracts.Runtime,
) {
	f(ctx, host, opts, runtime)
}

type hostEnricherFunc func(*models.Host, *ARPCache)

func (f hostEnricherFunc) Enrich(host *models.Host, arp *ARPCache) {
	f(host, arp)
}

type osDetectorFunc func([]models.Port) (string, string)

func (f osDetectorFunc) Detect(ports []models.Port) (string, string) {
	return f(ports)
}

var (
	_ nameCache  = (*mdnsCache)(nil)
	_ icmpProber = (*ICMPScanner)(nil)
)
