package arp

import "strings"

// ouiDatabase contains common MAC address prefixes and their vendors.
var ouiDatabase = map[string]string{
	// Apple
	"00:03:93": "Apple", "00:1b:63": "Apple", "28:cf:da": "Apple",
	"3c:07:54": "Apple", "70:de:e2": "Apple", "a8:66:7f": "Apple",
	// Microsoft
	"00:15:5d": "Microsoft", "00:50:f2": "Microsoft", "28:18:78": "Microsoft",
	// Intel
	"00:1b:21": "Intel", "3c:a9:f4": "Intel", "68:05:ca": "Intel",
	// Samsung
	"00:15:99": "Samsung", "34:c3:ac": "Samsung", "94:35:0a": "Samsung",
	// Cisco
	"00:00:0c": "Cisco", "00:01:42": "Cisco", "00:02:17": "Cisco",
	// Dell
	"00:14:22": "Dell", "14:18:77": "Dell", "b8:ac:6f": "Dell",
	// HP
	"00:14:38": "HP", "3c:d9:2b": "HP", "94:57:a5": "HP",
	// Lenovo
	"00:1e:4c": "Lenovo", "28:d2:44": "Lenovo", "50:46:5d": "Lenovo",
	// TP-Link
	"14:cc:20": "TP-Link", "50:3a:a0": "TP-Link", "c0:4a:00": "TP-Link",
	// Netgear
	"00:14:6c": "Netgear", "28:80:88": "Netgear", "a0:21:b7": "Netgear",
	// Amazon
	"00:fc:8b": "Amazon", "44:65:0d": "Amazon", "fc:65:de": "Amazon",
	// Google
	"3c:5a:b4": "Google", "94:eb:2c": "Google", "f4:f5:d8": "Google",
	// Huawei
	"00:e0:fc": "Huawei", "04:02:1f": "Huawei", "10:47:80": "Huawei",
	// Raspberry Pi
	"b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
	// Ubiquiti
	"00:27:22": "Ubiquiti", "74:83:c2": "Ubiquiti", "fc:ec:da": "Ubiquiti",
	// VMware
	"00:0c:29": "VMware", "00:50:56": "VMware",
	// VirtualBox
	"08:00:27": "VirtualBox",
	// Synology
	"00:11:32": "Synology",
	// QNAP
	"00:08:9b": "QNAP",
	// ASUS
	"00:1a:92": "ASUS", "04:92:26": "ASUS", "14:dd:a9": "ASUS",
	// D-Link
	"00:05:5d": "D-Link", "1c:7e:e5": "D-Link", "28:10:7b": "D-Link",
	// Linksys
	"00:14:bf": "Linksys", "20:aa:4b": "Linksys", "c0:56:27": "Linksys",
	// Sony
	"00:04:1f": "Sony", "00:13:a9": "Sony", "28:0d:fc": "Sony",
	// LG
	"00:1c:62": "LG", "10:68:3f": "LG", "64:99:5d": "LG",
	// Xiaomi
	"00:9e:c8": "Xiaomi", "28:6c:07": "Xiaomi", "64:b4:73": "Xiaomi",
}

// LookupVendor looks up the vendor for a MAC address.
func LookupVendor(mac string) string {
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return ""
	}
	oui := strings.Join(parts[:3], ":")
	if vendor, ok := ouiDatabase[oui]; ok {
		return vendor
	}
	return ""
}
