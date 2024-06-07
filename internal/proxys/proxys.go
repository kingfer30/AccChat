package proxys

import (
	"sync"
)

var Ips sync.Map

func SetProxy(ips []string) {
	for i, v := range ips {
		Ips.Store(i, v)
	}
}

func GetProxyIP() string {
	var randomProxy = ""
	Ips.Range(func(key, value any) bool {
		randomProxy = value.(string)
		return false // 返回 false，表示只获取一个代理IP即可
	})
	return randomProxy
}
