package main

import (
	"fmt"
	"math/rand"
)

// Диапазоны Cloudflare WARP anycast. Первые 8+7 — ровно WARP_PREFIXES из
// warp-wireproxy-native.sh (162.159.192-195, 188.114.96-99 и семь разрозненных
// /24 в 8.0.0.0/8, доставшихся Cloudflare исторически). Последние 4
// (188.114.100-103) в bash-версии нет — добавлены по независимому источнику,
// см. https://github.com/Shellgate/warp-endpoint (warpip.sh), а не наугад.
var warpPrefixes = []string{
	"162.159.192", "162.159.193", "162.159.194", "162.159.195",
	"188.114.96", "188.114.97", "188.114.98", "188.114.99",
	"8.34.146", "8.39.214", "8.39.204", "8.6.112", "8.35.211", "8.39.125", "8.47.69",
	"188.114.100", "188.114.101", "188.114.102", "188.114.103",
}

var warpPorts = []int{
	500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939,
	942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070,
	1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854,
	4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
	8742, 8854, 8886,
}

func knownGoodEndpoints() []string {
	return []string{
		"188.114.96.10:2408",
		"188.114.97.10:2408",
		"162.159.192.244:1843",
		"162.159.195.100:1010",
	}
}

func randomEndpoints(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		prefix := warpPrefixes[rand.Intn(len(warpPrefixes))]
		octet := rand.Intn(256)
		port := warpPorts[rand.Intn(len(warpPorts))]
		out = append(out, fmt.Sprintf("%s.%d:%d", prefix, octet, port))
	}
	return out
}
