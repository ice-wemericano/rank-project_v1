package logs

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	mu    sync.Mutex
	files = map[string]*os.File{}
)

// 경로 찾고
func fileFor(tag string) *os.File {
	key := strings.ToLower(tag)
	if f, ok := files[key]; ok {
		return f
	}
	if err := os.MkdirAll("logs", 0755); err != nil {
		return nil
	}
	f, err := os.OpenFile("logs/log_"+key+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil
	}
	files[key] = f
	return f
}

// 해당 경로에 로그 찍기
func Log(tag, msg string) {
	now := time.Now()
	line := fmt.Sprintf("%s%03d [%s] %s\n", now.Format("2006_01_02_15:04:"), now.Nanosecond()/1e6, tag, msg)

	fmt.Print(line)

	mu.Lock()
	defer mu.Unlock()
	f := fileFor(tag)
	if f == nil {
		return
	}
	_, _ = f.WriteString(line)
	_ = f.Sync()
}
