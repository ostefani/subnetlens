// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"embed"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"sync"

	arptransport "github.com/ostefani/subnetlens/transports/arp"
)

type ARPCache = arptransport.Cache

type ARPTable = arptransport.Table

const ouiFile = "oui.csv"

//go:embed oui.csv
var embeddedData embed.FS
var (
	OUITable = make(map[string]string)
)

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
	table, _ := arptransport.ReadTable()
	return table
}

// Converts any common MAC format to lowercase colon-separated.
func normaliseMAC(s string) string {
	return arptransport.NormalizeMAC(s)
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
