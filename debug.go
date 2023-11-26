package tcpip

import (
	"log"
)

func debug(v ...interface{}) {
	if enableDebugLog == nil || !*enableDebugLog {
		return
	}
	log.Println(v...)
}

func debugf(format string, v ...interface{}) {
	if enableDebugLog == nil || !*enableDebugLog {
		return
	}
	log.Printf(format, v...)
}
