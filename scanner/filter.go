// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ostefani/subnetlens/models"
)

// Filter grammar (shared by the --filter flag and the TUI initial filter):
//
//	expr    := condition ("," condition)*
//	condition := key ":" value | bare
//
// Comma separates AND conditions; repeating a key ORs its values
// ("port:22,port:80" matches hosts with either port open). String values
// match case-insensitively as substrings. A bare term without a colon
// matches when any of IP, hostname, MAC, vendor, OS, or device contains it.
//
// Keys: ip, host (alias: hostname), mac, vendor, os, device, service
// (open-port service substring), port (open-port number 1-65535),
// weak and alive (true/false), source (exact discovery source).
var filterKeys = []string{
	"ip", "host", "hostname", "mac", "vendor", "os", "device",
	"service", "port", "weak", "alive", "source",
}

type filterCondition struct {
	key    string
	values []filterValue
}

// filterValue is a parsed condition value. Text is lowercased once at parse
// time for substring keys (with runes precomputed for the allocation-free
// matcher); port and boolean values are parsed once into num/set.
type filterValue struct {
	text  string
	runes []rune
	num   int
	set   bool
}

// HostFilter is a compiled --filter expression. A nil *HostFilter matches
// every host; use ParseHostFilter and keep the nil instead of branching.
type HostFilter struct {
	expr       string
	conditions []filterCondition
}

// ParseHostFilter compiles expr. Empty (or whitespace-only) input returns a
// nil filter that matches everything. Anything else that does not parse is a
// hard error: filters fail fast so a typo never silently narrows a scan.
func ParseHostFilter(expr string) (*HostFilter, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil, nil
	}
	grouped := make(map[string][]string)
	var order []string
	for _, raw := range strings.Split(trimmed, ",") {
		segment := strings.TrimSpace(raw)
		if segment == "" {
			return nil, fmt.Errorf("invalid --filter %q: empty condition (stray comma?)", expr)
		}
		key, value := splitFilterSegment(segment)
		if err := validateFilterValue(expr, key, value); err != nil {
			return nil, err
		}
		if _, seen := grouped[key]; !seen {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], value)
	}
	conditions := make([]filterCondition, 0, len(order))
	for _, key := range order {
		raw := grouped[key]
		values := make([]filterValue, 0, len(raw))
		for _, value := range raw {
			values = append(values, makeFilterValue(key, value))
		}
		conditions = append(conditions, filterCondition{key: key, values: values})
	}
	return &HostFilter{expr: trimmed, conditions: conditions}, nil
}

// makeFilterValue canonicalizes one validated value. It runs once per
// distinct key/value at parse time so Matches stays allocation-free.
func makeFilterValue(key, value string) filterValue {
	switch key {
	case "port":
		num, _ := strconv.Atoi(value) // validated by validateFilterValue
		return filterValue{num: num}
	case "weak", "alive":
		set, _ := strconv.ParseBool(strings.ToLower(value)) // validated
		return filterValue{set: set}
	case "source":
		return filterValue{text: value}
	default:
		fold := strings.ToLower(value)
		return filterValue{text: fold, runes: []rune(fold)}
	}
}

// Expression returns the normalized source expression for status lines.
func (f *HostFilter) Expression() string {
	if f == nil {
		return ""
	}
	return f.expr
}

// Matches reports whether the snapshot satisfies every condition. A nil
// filter matches everything.
func (f *HostFilter) Matches(snapshot models.HostSnapshot) bool {
	if f == nil {
		return true
	}
	for _, condition := range f.conditions {
		if !matchFilterCondition(condition, snapshot) {
			return false
		}
	}
	return true
}

// FilterSnapshots returns the snapshots satisfying f (nil-safe).
func (f *HostFilter) FilterSnapshots(snapshots []models.HostSnapshot) []models.HostSnapshot {
	if f == nil {
		return snapshots
	}
	kept := make([]models.HostSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if f.Matches(snapshot) {
			kept = append(kept, snapshot)
		}
	}
	return kept
}

// FilterHosts returns the hosts whose snapshots satisfy f (nil-safe).
func (f *HostFilter) FilterHosts(hosts []*models.Host) []*models.Host {
	if f == nil {
		return hosts
	}
	kept := make([]*models.Host, 0, len(hosts))
	for _, host := range hosts {
		if host == nil {
			continue
		}
		if f.Matches(host.Snapshot()) {
			kept = append(kept, host)
		}
	}
	return kept
}

func splitFilterSegment(segment string) (key, value string) {
	key, value, found := strings.Cut(segment, ":")
	if !found {
		return "any", strings.ToLower(strings.TrimSpace(segment))
	}
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	if key == "hostname" {
		key = "host"
	}
	return key, value
}

func validateFilterValue(expr, key, value string) error {
	known := key == "any"
	for _, candidate := range filterKeys {
		if key == candidate {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("invalid --filter %q: unknown key %q (want one of %s, or a bare search term)", expr, key, strings.Join(filterDisplayKeys(), ", "))
	}
	if value == "" {
		return fmt.Errorf("invalid --filter %q: empty value for key %q", expr, key)
	}
	switch key {
	case "port":
		number, err := strconv.Atoi(value)
		if err != nil || number < 1 || number > 65535 {
			return fmt.Errorf("invalid --filter %q: port needs a number 1-65535, got %q", expr, value)
		}
	case "weak", "alive":
		if _, err := strconv.ParseBool(strings.ToLower(value)); err != nil {
			return fmt.Errorf("invalid --filter %q: %s needs true/false, got %q", expr, key, value)
		}
	}
	return nil
}

func filterDisplayKeys() []string {
	keys := make([]string, 0, len(filterKeys))
	for _, key := range filterKeys {
		if key == "hostname" {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

func matchFilterCondition(condition filterCondition, snapshot models.HostSnapshot) bool {
	for _, value := range condition.values {
		if matchFilterValue(condition.key, value, snapshot) {
			return true
		}
	}
	return false
}

func matchFilterValue(key string, value filterValue, snapshot models.HostSnapshot) bool {
	switch key {
	case "any":
		return foldContains(snapshot.IP, value) ||
			foldContains(snapshot.Hostname, value) ||
			foldContains(snapshot.MAC, value) ||
			foldContains(snapshot.Vendor, value) ||
			foldContains(snapshot.OS, value) ||
			foldContains(snapshot.Device, value)
	case "ip":
		return foldContains(snapshot.IP, value)
	case "host":
		return foldContains(snapshot.Hostname, value)
	case "mac":
		return foldContains(snapshot.MAC, value)
	case "vendor":
		return foldContains(snapshot.Vendor, value)
	case "os":
		return foldContains(snapshot.OS, value)
	case "device":
		return foldContains(snapshot.Device, value)
	case "service":
		for _, port := range snapshot.OpenPorts() {
			if foldContains(port.Service, value) {
				return true
			}
		}
		return false
	case "port":
		for _, port := range snapshot.OpenPorts() {
			if port.Number == value.num {
				return true
			}
		}
		return false
	case "weak":
		return snapshot.Weak == value.set
	case "alive":
		return snapshot.Alive == value.set
	case "source":
		return strings.EqualFold(string(snapshot.Source), value.text)
	default:
		return false
	}
}

// foldContains reports whether the pre-lowered needle is a substring of
// haystack, case-insensitively, without allocating. The exact-case fast path
// covers already-lowercase data (IPs, most hostnames); the rune scan folds
// the haystack on the fly for the rest.
func foldContains(haystack string, needle filterValue) bool {
	if len(needle.runes) == 0 {
		return true
	}
	if strings.Contains(haystack, needle.text) {
		return true
	}
	for i := 0; i < len(haystack); {
		if matchFoldAt(haystack[i:], needle.runes) {
			return true
		}
		_, size := utf8.DecodeRuneInString(haystack[i:])
		if size == 0 {
			return false
		}
		i += size
	}
	return false
}

func matchFoldAt(s string, needle []rune) bool {
	for _, want := range needle {
		r, size := utf8.DecodeRuneInString(s)
		if size == 0 || unicode.ToLower(r) != want {
			return false
		}
		s = s[size:]
	}
	return true
}
