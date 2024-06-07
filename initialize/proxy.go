package initialize

import (
	"bufio"
	"freechatgpt/internal/proxys"
	"os"
	"strings"
)

func InitProxy() {
	var proxies []string
	// first check for proxies.txt
	proxies = []string{}
	if _, err := os.Stat("proxies.txt"); err == nil {
		// Each line is a proxy, put in proxies array
		file, _ := os.Open("proxies.txt")
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// Split line by :
			proxy := scanner.Text()
			proxy_parts := strings.Split(proxy, ":")
			if len(proxy_parts) > 1 {
				proxies = append(proxies, proxy)
			} else {
				continue
			}
		}
	}
	// if no proxies, then check env http_proxy
	if len(proxies) == 0 {
		proxy := os.Getenv("http_proxy")
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}
	proxys.SetProxy(proxies)
}
