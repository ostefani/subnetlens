package scanner

import (
	"bufio"
	"embed"
	"encoding/csv"
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

type ARPCache struct {
	mu       sync.Mutex
	table    ARPTable
	overlay  ARPTable
	lastRead time.Time
}

type ARPTable map[string]string

func (c *ARPCache) Lookup(ip string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.table == nil || time.Since(c.lastRead) > 500*time.Millisecond {
		c.table = ReadARPTable()
		c.mergeOverlayLocked()
		c.lastRead = time.Now()
	}

	mac, ok := c.table[ip]
	return mac, ok
}

func (c *ARPCache) Refresh() ARPTable {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.table = ReadARPTable()
	c.mergeOverlayLocked()
	c.lastRead = time.Now()
	return c.table
}

func (c *ARPCache) Inject(ip, mac string) {
	mac = normaliseMAC(mac)
	if mac == "" || ip == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.overlay == nil {
		c.overlay = make(ARPTable)
	}
	c.overlay[ip] = mac
	if c.table != nil {
		c.table[ip] = mac
	}
}

func (c *ARPCache) mergeOverlayLocked() {
	if c.overlay == nil {
		return
	}
	if c.table == nil {
		c.table = make(ARPTable)
	}
	for ip, mac := range c.overlay {
		c.table[ip] = mac
	}
}

const ouiFile = "oui.csv"

//go:embed oui.csv
var embeddedData embed.FS
var (
	OUITable = make(map[string]string)
)

// ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
var darwinARPRe = regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)`)

// 192.168.1.1 aa-bb-cc-dd-ee-ff dynamic
var windowsARPRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-:]{17})`)
var linuxARPRe = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+([0-9a-f:]+)`)

var identity = func(s string) string { return s }

// ouiOnce ensures LoadOUICSV's writes to OUITable complete fully before any
// goroutine calls VendorFromMAC.
var ouiOnce sync.Once

// Parse the embedded oui.csv into OUITable.
func LoadOUICSV() error {
	var loadErr error

	ouiOnce.Do(func() {
		ouiFileReader, err := embeddedData.Open(ouiFile)
		if err != nil {
			loadErr = fmt.Errorf("open embedded %s: %w", ouiFile, err)
			return
		}
		defer ouiFileReader.Close()

		reader := csv.NewReader(ouiFileReader)
		reader.FieldsPerRecord = -1

		// Skip the header row.
		reader.Read()

		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				loadErr = fmt.Errorf("read OUI CSV row: %w", err)
				return
			}
			if len(record) >= 3 {
				oui := strings.ToUpper(strings.TrimSpace(record[1]))
				oui = strings.NewReplacer(":", "", "-", "").Replace(oui)
				OUITable[oui] = strings.TrimSpace(record[2])
			}
		}

		debugLog("arp", "LoadOUICSV loaded %d entries from %s", len(OUITable), ouiFile)
	})

	return loadErr
}

func ReadARPTable() ARPTable {
	table := make(ARPTable)

	var err error
	switch runtime.GOOS {
	case "linux":
		err = readARPLinux(table)
	case "darwin":
		err = readARPDarwin(table)
	case "windows":
		err = readARPWindows(table)
	default:
		debugLog("arp", "unsupported OS %q — ARP enrichment disabled", runtime.GOOS)
		return table
	}

	if err != nil {
		debugLog("arp", "ReadARPTable error: %v", err)
	}

	return table
}

func parseARPLines(table ARPTable, r io.Reader, re *regexp.Regexp, transform func(string) string, skipHeader bool) error {
	sc := bufio.NewScanner(r)
	if skipHeader {
		sc.Scan()
	}
	for sc.Scan() {
		matches := re.FindStringSubmatch(transform(sc.Text()))
		if matches == nil {
			continue
		}
		mac := normaliseMAC(matches[2])
		if mac == "" {
			continue
		}
		table[matches[1]] = mac
	}
	return sc.Err()
}

func readARPLinux(table ARPTable) error {
	fileReader, err := os.Open("/proc/net/arp")

	if err != nil {
		return fmt.Errorf("open /proc/net/arp: %w", err)
	}

	defer fileReader.Close()
	return parseARPLines(table, fileReader, linuxARPRe, identity, true)
}

func readARPFromCommand(table ARPTable, args []string, re *regexp.Regexp, transform func(string) string) error {
	out, err := exec.Command("arp", args...).Output()

	if err != nil {
		return fmt.Errorf("arp %v: %w", args, err)
	}

	return parseARPLines(table, strings.NewReader(string(out)), re, transform, false)
}

func readARPDarwin(table ARPTable) error {
	return readARPFromCommand(table, []string{"-an"}, darwinARPRe, func(s string) string { return s })
}

func readARPWindows(table ARPTable) error {
	return readARPFromCommand(table, []string{"-a"}, windowsARPRe, strings.ToLower)
}

// Converts any common MAC format to lowercase colon-separated.
func normaliseMAC(s string) string {
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

func VendorFromMAC(mac string) string {
	if len(mac) < 8 {
		return ""
	}

	oui := strings.ToUpper(strings.ReplaceAll(mac[:8], ":", ""))

	if vendor, ok := OUITable[oui]; ok {
		return vendor
	}

	if vendor, ok := localTable[oui]; ok {
		return vendor
	}

	return ""
}

// Full registry: https://regauth.standards.ieee.org
var localTable = map[string]string{
	// Apple
	"001CB3": "Apple", "002332": "Apple", "0026BB": "Apple", "286ABA": "Apple",
	"3C0754": "Apple", "3C15C2": "Apple", "3C2EFF": "Apple", "6C4008": "Apple",
	"70EC5A": "Apple", "7C6D62": "Apple", "A45E60": "Apple", "AC3C0B": "Apple",
	"B8FF61": "Apple", "D0E140": "Apple", "F0DBF8": "Apple", "F82793": "Apple",

	// TP-Link
	"1027F5": "TP-Link", "1C61B4": "TP-Link", "50C7BF": "TP-Link", "6427E3": "TP-Link",
	"B0487A": "TP-Link", "E848B8": "TP-Link", "F4F26D": "TP-Link",

	// Netgear
	"001B2F": "Netgear", "20E52A": "Netgear", "2CB05D": "Netgear",
	"6CB0CE": "Netgear", "A040A0": "Netgear", "C03F0E": "Netgear",

	// ASUS
	"049226": "ASUS", "107B44": "ASUS", "1C872C": "ASUS", "2C56DC": "ASUS",
	"50465D": "ASUS", "AC9E17": "ASUS", "F8328C": "ASUS",

	// Sony
	"0013A9": "Sony", "001A80": "Sony", "002AD2": "Sony",
	"30179B": "Sony", "AC9B0A": "Sony", "F8D0AC": "Sony",

	// Microsoft / Xbox
	"00155D": "Microsoft", "0017FA": "Microsoft", "002248": "Microsoft",
	"28183C": "Microsoft", "7C1E52": "Microsoft",
}
