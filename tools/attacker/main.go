// 조회수 방어 테스트용 트래픽 생성기 (본인 시스템 점검용).
//
// 각 모드는 특정 방어 레벨을 뚫는 수법을 흉내 낸다. 돌리면 보낸 요청 수와
// 실제 반영/미반영(사유별) 집계를 출력한다. 대시보드와 비교해보면 된다.
//
// 사용 예:
//
//	go run ./tools/attacker -url http://localhost:9090 -id 1 -mode naive   -n 50
//	go run ./tools/attacker -url https://rank.neverwe.com -id 1 -mode spoofip -n 200 -c 20
//
// 모드별 겨냥 레벨:
//
//	naive    같은 신원으로 반복        → Lv0 돌파 (Lv1부터 중복으로 막힘)
//	fresh    매 요청 새 신원(쿠키 없음) → Lv1 돌파 (Lv2부터 IP로 막힘)
//	spoofip  fresh + X-Forwarded-For 위조 → Lv2 돌파 (Lv3 부터 실제 IP 로 판정해 막힘)
//	browser  spoofip + 브라우저 헤더 위장  → (실제 IP 가 여러 개면) Lv4 돌파
//	proof    browser + open→체류→PoW→view 정식흐름 → (실제 IP 가 여러 개면) Lv5 돌파
//
// Lv3 이상은 "실제 접속 IP 당 하루 1회"라서, 한 PC 에서는 모드와 상관없이 글당 1회만 반영된다.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
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
	ProofToken   string `json:"proof_token"`
	MinDwellMS   int64  `json:"min_dwell_ms"`
	PoWChallenge string `json:"pow_challenge"`
	PoWBits      int    `json:"pow_bits"`
}

// solvePoW 는 sha256(challenge+":"+n) 의 선행 0 비트가 bits 이상인 n 을 찾는다(서버 CheckPoW 와 동일).
func solvePoW(challenge string, bits int) string {
	for n := 0; ; n++ {
		s := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(challenge + ":" + s))
		ok := true
		for i := 0; i < bits; i++ {
			if sum[i/8]&(0x80>>(i%8)) != 0 {
				ok = false
				break
			}
		}
		if ok {
			return s
		}
	}
}

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
const browserAccept = "*/*"
const browserLang = "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"

// referer 는 browser 모드에서 붙일 글 페이지 주소(동일 출처 Referer 검사 통과용).
var referer string

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
	if !strings.Contains(base, "://") {
		base = "http://" + base // localhost:9090 처럼 스킴 없이 줘도 동작
	}

	spoof := *mode == "spoofip" || *mode == "browser" || *mode == "proof"
	browser := *mode == "browser" || *mode == "proof"
	useProof := *mode == "proof"
	// naive 는 하나의 신원(쿠키 공유), 나머지는 매 요청 새 신원
	shared := *mode == "naive"

	referer = fmt.Sprintf("%s/post.html?id=%d", base, *id)
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
	pt, pow := "", ""
	if useProof {
		o := doOpen(client, openURL, ip, browser)
		pt, dwell := o.ProofToken, o.MinDwellMS
		if o.PoWChallenge != "" {
			pow = solvePoW(o.PoWChallenge, o.PoWBits)
		}
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
		u += "&pt=" + url.QueryEscape(pt) + "&pow=" + url.QueryEscape(pow)
	}
	return doView(client, u, ip, spoof, browser)
}

func doOpen(client *http.Client, u, ip string, browser bool) openResp {
	var o openResp
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return o
	}
	setHeaders(req, ip, true, browser) // open 은 항상 IP 위조 허용
	resp, err := client.Do(req)
	if err != nil {
		recordErr(err.Error())
		return o
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &o)
	return o
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
		req.Header.Set("Accept-Language", browserLang)
		req.Header.Set("Referer", referer)
	}
}
