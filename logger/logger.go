package logger

import (
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	Gray   = "\033[37m"
)

type LogEntry struct {
	Timestamp int64  `json:"timestamp"`
	Prefix    string `json:"prefix"`
	Message   string `json:"message"`
	Color     string `json:"color"`
}

var (
	subscribers = make(map[chan LogEntry]bool)
	subMu       sync.Mutex
	buffer      []LogEntry
	bufMu       sync.Mutex
	MaxBuffer   = 100
)

func Subscribe() chan LogEntry {
	subMu.Lock()
	defer subMu.Unlock()
	ch := make(chan LogEntry, 100)
	subscribers[ch] = true
	
	bufMu.Lock()
	for _, entry := range buffer {
		select {
		case ch <- entry:
		default:
		}
	}
	bufMu.Unlock()
	
	return ch
}

func Unsubscribe(ch chan LogEntry) {
	subMu.Lock()
	defer subMu.Unlock()
	delete(subscribers, ch)
	close(ch)
}

func broadcast(entry LogEntry) {
	bufMu.Lock()
	buffer = append(buffer, entry)
	if len(buffer) > MaxBuffer {
		buffer = buffer[1:]
	}
	bufMu.Unlock()

	subMu.Lock()
	defer subMu.Unlock()
	for ch := range subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
}

func logMsg(color, prefix, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	log.Printf("%s[%s]%s %s", color, prefix, Reset, msg)
	
	broadcast(LogEntry{
		Timestamp: time.Now().Unix(),
		Prefix:    prefix,
		Message:   msg,
		Color:     color,
	})
}

func Info(prefix, format string, v ...interface{}) {
	logMsg(Cyan, prefix, format, v...)
}

func Success(prefix, format string, v ...interface{}) {
	logMsg(Green, prefix, format, v...)
}

func Warn(prefix, format string, v ...interface{}) {
	logMsg(Yellow, prefix, format, v...)
}

func Error(prefix, format string, v ...interface{}) {
	logMsg(Red, prefix, format, v...)
}

func VPN(format string, v ...interface{}) {
	logMsg(Purple, "VPN", format, v...)
}

func P2P(format string, v ...interface{}) {
	logMsg(Blue, "P2P", format, v...)
}

func RYNE(format string, v ...interface{}) {
	logMsg(Purple, "RYNE", format, v...)
}

func Solana(format string, v ...interface{}) {
	logMsg(Yellow, "SOLANA", format, v...)
}