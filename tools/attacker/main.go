// 조회수 방어 테스트용 트래픽 생성기 (본인 시스템 점검용).
//
// 각 모드는 특정 방어 레벨을 뚫는 수법을 흉내 낸다. 돌리면 보낸 요청 수와
// 실제 반영/미반영(사유별) 집계를 출력한다. 대시보드와 비교해보면 된다.
//
// 사용 예:
//   go run ./tools/attacker -url http://localhost:9090 -id 1 -mode naive   -n 50
//   go run ./tools/attacker -url https://rank.neverwe.com -id 1 -mode spoofip -n 200 -c 20
//
// 모드별 겨냥 레벨:
//   naive    같은 신원으로 반복        → Lv0 돌파 (Lv1부터 중복으로 막힘)
//   fresh    매 요청 새 신원(쿠키 없음) → Lv1 돌파 (Lv2부터 IP로 막힘)
//   spoofip  fresh + X-Forwarded-For 위조 → Lv2·Lv3 돌파 (Lv4 봇판별로 막힘)
//   browser  spoofip + 브라우저 헤더 위장  → Lv4 돌파 (Lv5 열람증명으로 막힘)
//   proof    browser + open→체류→view 정식흐름 → Lv5까지 돌파
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// -k 지정 시 TLS 인증서 검증을 생략한다(자체서명 인증서 대상 테스트용).
var insecureTransport *http.Transport

// firstErr 는 처음 발생한 연결/파싱 에러 메시지를 한 번만 담아둔다(진단 출력용).
var (
	firstErr   string
	firstErrMu sync.Once
)

func recordErr(msg string) {
	firstErrMu.Do(func() { firstErr = msg })
}

type viewResp struct {
	Counted bool   `json:"counted"`
	Reason  string `json:"reason"`
	Level   int    `json:"level"`
}

type openResp struct {
	ProofToken string `json:"proof_token"`
	MinDwellMS int64  `json:"min_dwell_ms"`
}

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"

func newJar() (http.CookieJar, error) { return cookiejar.New(nil) }

// preflight 는 서버에 한 번 요청해 연결 + JSON 응답 여부를 확인한다. 문제가 있으면 메시지를 돌려준다.
func preflight(client *http.Client, viewURL string) string {
	resp, err := client.Get(viewURL)
	if err != nil {
		return err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	t := strings.TrimSpace(string(body))
	if len(t) == 0 || (t[0] != '{' && t[0] != '[') {
		return fmt.Sprintf("JSON 응답이 아님 (HTTP %d). http→https 리다이렉트이거나 주소가 틀렸을 수 있음.\n  → https 주소를 쓰고, 자체서명 인증서면 -k 를 붙이세요.\n  응답 앞부분: %.120s", resp.StatusCode, t)
	}
	return ""
}

func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(223)+1, rand.Intn(256), rand.Intn(256), rand.Intn(254)+1)
}

func main() {
	target := flag.String("url", "http://localhost:9090", "서버 주소")
	id := flag.Int("id", 1, "공격할 게시글 id")
	n := flag.Int("n", 100, "총 요청 수")
	c := flag.Int("c", 10, "동시 실행 수")
	mode := flag.String("mode", "naive", "naive|fresh|spoofip|browser|proof")
	insecure := flag.Bool("k", false, "TLS 인증서 검증 생략 (자체서명 인증서 대상)")
	flag.Parse()

	if *insecure {
		insecureTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	base := strings.TrimRight(*target, "/") // 끝 슬래시 제거 (// 방지)

	spoof := *mode == "spoofip" || *mode == "browser" || *mode == "proof"
	browser := *mode == "browser" || *mode == "proof"
	useProof := *mode == "proof"
	// naive 는 하나의 신원(쿠키 공유), 나머지는 매 요청 새 신원
	shared := *mode == "naive"

	viewURL := fmt.Sprintf("%s/api/posts/view?id=%d", base, *id)
	openURL := fmt.Sprintf("%s/api/posts/open?id=%d", base, *id)
	hbURL := fmt.Sprintf("%s/api/posts/heartbeat?id=%d", base, *id)

	var counted int64
	var mu sync.Mutex
	reasons := map[string]int{}

	tally := func(r viewResp) {
		if r.Counted {
			atomic.AddInt64(&counted, 1)
		}
		mu.Lock()
		reasons[r.Reason]++
		mu.Unlock()
	}

	// naive 모드는 하나의 신원(쿠키 공유). 나머지는 매 요청 새 신원.
	var sharedJar http.CookieJar
	newClient := func() *http.Client {
		c := &http.Client{Timeout: 15 * time.Second}
		if insecureTransport != nil {
			c.Transport = insecureTransport
		}
		if shared {
			c.Jar = sharedJar
		} else {
			c.Jar, _ = newJar()
		}
		return c
	}

	// 프리플라이트: 서버에 실제로 닿는지 먼저 확인한다.
	if msg := preflight(newClient(), viewURL); msg != "" {
		fmt.Printf("서버에 연결할 수 없습니다: %s\n\n확인하세요:\n"+
			"  1) 서버가 떠 있는지 (go run . 또는 rank.exe)\n"+
			"  2) -url 값이 맞는지 (현재: %s)\n"+
			"  3) HTTPS 인증서가 자체서명이면 -k 옵션을 붙이세요\n", msg, *target)
		return
	}

	start := time.Now()

	remaining := *n
	if shared {
		sharedJar, _ = newJar()
		// 쿠키를 먼저 확보해, 동시성 때문에 여러 건이 새는 것을 막는다(= 신원 1개 효과).
		if remaining > 0 {
			tally(attackOnce(newClient(), viewURL, openURL, hbURL, spoof, browser, useProof))
			remaining--
		}
	}

	jobs := make(chan int, remaining)
	for i := 0; i < remaining; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < *c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				tally(attackOnce(newClient(), viewURL, openURL, hbURL, spoof, browser, useProof))
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("\n===== 결과 (mode=%s, id=%d) =====\n", *mode, *id)
	fmt.Printf("보낸 요청 : %d\n", *n)
	fmt.Printf("반영됨    : %d  (%.1f%%)\n", counted, 100*float64(counted)/float64(*n))
	fmt.Printf("미반영    : %d\n", int64(*n)-counted)
	fmt.Println("사유 분포 :")
	for k, v := range reasons {
		fmt.Printf("   %-16s %d\n", k, v)
	}
	fmt.Printf("소요시간  : %s (%.0f req/s)\n", elapsed.Round(time.Millisecond), float64(*n)/elapsed.Seconds())
	if firstErr != "" {
		fmt.Printf("\n[에러 샘플] %s\n", firstErr)
	}
}

// attackOnce 는 한 번의 조회 시도를 수행한다.
// proof 모드면 open → (체류하는 동안 1초마다 heartbeat) → view 로 Lv5 열람증명을 흉내 낸다.
func attackOnce(client *http.Client, viewURL, openURL, hbURL string, spoof, browser, useProof bool) viewResp {
	ip := randomIP()
	pt := ""
	if useProof {
		var dwell int64
		pt, dwell = doOpen(client, openURL, ip, browser)
		if pt != "" {
			// 서버가 실제 체류를 heartbeat 로 누적하므로, 머무는 흉내로 heartbeat 를 보낸다.
			beats := int(dwell/1000) + 2
			for i := 0; i < beats; i++ {
				doHeartbeat(client, hbURL+"&pt="+url.QueryEscape(pt), ip, browser)
				time.Sleep(1 * time.Second)
			}
		}
	}
	u := viewURL
	if pt != "" {
		u += "&pt=" + url.QueryEscape(pt)
	}
	return doView(client, u, ip, spoof, browser)
}

func doOpen(client *http.Client, u, ip string, browser bool) (string, int64) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", 0
	}
	setHeaders(req, ip, true, browser) // open 은 항상 IP 위조 허용
	resp, err := client.Do(req)
	if err != nil {
		recordErr(err.Error())
		return "", 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var o openResp
	if json.Unmarshal(body, &o) != nil {
		return "", 0
	}
	return o.ProofToken, o.MinDwellMS
}

func doHeartbeat(client *http.Client, u, ip string, browser bool) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return
	}
	setHeaders(req, ip, true, browser)
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}
}

func doView(client *http.Client, u, ip string, spoof, browser bool) viewResp {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return viewResp{Reason: "req_error"}
	}
	setHeaders(req, ip, spoof, browser)
	resp, err := client.Do(req)
	if err != nil {
		recordErr(err.Error())
		return viewResp{Reason: "conn_error"}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var v viewResp
	if json.Unmarshal(body, &v) != nil {
		return viewResp{Reason: "parse_error"}
	}
	return v
}

func setHeaders(req *http.Request, ip string, spoof, browser bool) {
	if spoof {
		req.Header.Set("X-Forwarded-For", ip) // Lv2 IP 중복제거 우회
	}
	if browser {
		req.Header.Set("User-Agent", browserUA) // Lv4 봇판별 우회
		req.Header.Set("Accept", browserAccept)
	}
}
