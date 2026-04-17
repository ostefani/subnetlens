// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package arp

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Cache struct {
	mu        sync.Mutex
	table     Table
	overlay   Table
	lastRead  time.Time
	onError   func(error)
	lastErr   string
	readTable func() (Table, error)
}

type Table map[string]string

var darwinARPRe = regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)`)
var windowsARPRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-:]{17})`)
var linuxARPRe = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+([0-9a-f:]+)`)

var identity = func(s string) string { return s }

func (c *Cache) Lookup(ip string) (string, bool) {
	var report func(error)
	var reportErr error

	c.mu.Lock()
	if c.table == nil || time.Since(c.lastRead) > 500*time.Millisecond {
		table, err := c.tableReaderLocked()()
		c.applyReadResultLocked(table, err)
		c.lastRead = time.Now()
		report, reportErr = c.captureErrorReportLocked(err)
	}

	mac, ok := c.table[ip]
	c.mu.Unlock()

	if report != nil {
		report(reportErr)
	}
	return mac, ok
}

func (c *Cache) Refresh() Table {
	var report func(error)
	var reportErr error

	c.mu.Lock()
	table, err := c.tableReaderLocked()()
	c.applyReadResultLocked(table, err)
	c.lastRead = time.Now()
	report, reportErr = c.captureErrorReportLocked(err)
	refreshed := c.table
	c.mu.Unlock()

	if report != nil {
		report(reportErr)
	}
	return refreshed
}

func (c *Cache) tableReaderLocked() func() (Table, error) {
	if c != nil && c.readTable != nil {
		return c.readTable
	}
	return ReadTable
}

func (c *Cache) applyReadResultLocked(table Table, err error) {
	if err == nil || c.table == nil {
		next := make(Table, len(table)+len(c.overlay))
		for k, v := range table {
			next[k] = v
		}
		c.table = next
	}
	c.mergeOverlayLocked()
}

func (c *Cache) Inject(ip, mac string) {
	mac = NormalizeMAC(mac)
	if mac == "" || ip == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.overlay == nil {
		c.overlay = make(Table)
	}
	c.overlay[ip] = mac
	if c.table != nil {
		c.table[ip] = mac
	}
}

func (c *Cache) mergeOverlayLocked() {
	if c.overlay == nil {
		return
	}
	if c.table == nil {
		c.table = make(Table)
	}
	for ip, mac := range c.overlay {
		c.table[ip] = mac
	}
}

func (c *Cache) SetErrorHandler(handler func(error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onError = handler
}

func (c *Cache) captureErrorReportLocked(err error) (func(error), error) {
	if err == nil {
		c.lastErr = ""
		return nil, nil
	}

	msg := err.Error()
	if msg == c.lastErr {
		return nil, nil
	}
	c.lastErr = msg
	return c.onError, err
}

func ReadTable() (Table, error) {
	table := make(Table)
	var err error

	switch runtime.GOOS {
	case "linux":
		err = readLinux(table)
	case "darwin":
		err = readDarwin(table)
	case "windows":
		err = readWindows(table)
	default:
		err = fmt.Errorf("ARP table reading is unsupported on %s", runtime.GOOS)
	}

	return table, err
}

func parseLines(table Table, r io.Reader, re *regexp.Regexp, transform func(string) string, skipHeader bool) error {
	sc := bufio.NewScanner(r)
	if skipHeader {
		sc.Scan()
	}
	for sc.Scan() {
		matches := re.FindStringSubmatch(transform(sc.Text()))
		if matches == nil {
			continue
		}
		mac := NormalizeMAC(matches[2])
		if mac == "" {
			continue
		}
		table[matches[1]] = mac
	}
	return sc.Err()
}

func readLinux(table Table) error {
	fileReader, err := os.Open("/proc/net/arp")
	if err != nil {
		return fmt.Errorf("open /proc/net/arp: %w", err)
	}
	defer fileReader.Close()
	return parseLines(table, fileReader, linuxARPRe, identity, true)
}

func readARPFromCommand(table Table, args []string, re *regexp.Regexp, transform func(string) string) error {
	out, err := exec.Command("arp", args...).Output()
	if err != nil {
		return fmt.Errorf("arp %v: %w", args, err)
	}
	return parseLines(table, strings.NewReader(string(out)), re, transform, false)
}

func readDarwin(table Table) error {
	return readARPFromCommand(table, []string{"-an"}, darwinARPRe, identity)
}

func readWindows(table Table) error {
	return readARPFromCommand(table, []string{"-a"}, windowsARPRe, strings.ToLower)
}

func NormalizeMAC(s string) string {
	clean := strings.ToLower(strings.NewReplacer("-", "", ":", "", ".", "").Replace(s))
	if len(clean) != 12 {
		return ""
	}
	for _, c := range clean {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		clean[0:2], clean[2:4], clean[4:6],
		clean[6:8], clean[8:10], clean[10:12])
}
