package db

import (
	"errors"
	"strings"
	"time"
)

// ErrNoDB 는 아직 DB 연결이 준비되지 않았을 때(NAS 다운 등) 반환된다.
var ErrNoDB = errors.New("database not ready")

// Post 는 게시판 글 한 건.
type Post struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Owner     string `json:"owner"`
	ViewCount int    `json:"view_count"`
	Level     int    `json:"level"` // 현재 이 글에 적용된 방어 레벨 (핸들러에서 채움)
}

// ViewEvent 는 조회 시도 기록 한 건.
type ViewEvent struct {
	PostID    int
	IP        string
	Token     string
	UserAgent string
	Reason    string
	Counted   bool
	CreatedAt time.Time
}

// PostStats 는 대시보드용 게시판별 집계.
type PostStats struct {
	ID        int            `json:"id"`
	Title     string         `json:"title"`
	Owner     string         `json:"owner"`
	Level     int            `json:"level"`      // 이 게시글에 적용된 방어 레벨
	ViewCount int            `json:"view_count"` // 실제 반영된 조회수
	Total     int            `json:"total"`      // 전체 요청 수
	Reflected int            `json:"reflected"`  // 반영된 수(인라인 통과 - 스크럽 전 기준)
	Rejected  int            `json:"rejected"`   // 반영 안 된 수(인라인에서 걸러짐)
	Reasons   map[string]int `json:"reasons"`    // 미반영 사유별 수

	// Lv6 사후 스크러빙: 인라인 통과(reflected) 중 나중에 소급 차감된 수.
	// view_count = reflected - scrubbed (순 확정 조회수).
	Scrubbed     int            `json:"scrubbed"`      // 소급 차감된 수
	ScrubReasons map[string]int `json:"scrub_reasons"` // 소급 차감 사유별 수

	// 급증 감지 (최근 TrendMinutes 분, 분 단위)
	PerMin   int     `json:"per_min"`  // 최근 1분 시도 수
	Baseline float64 `json:"baseline"` // 그 전 BaselineMinutes 분의 분당 평균
	Spike    bool    `json:"spike"`    // 평소보다 급증
	Trend    []int   `json:"trend"`    // 분당 시도 수, 오래된 것 → 최근 순
}

// 급증 판정 기준 (실습하면서 조절해도 된다).
const (
	TrendMinutes    = 15 // 대시보드에 그릴 분당 그래프 길이
	BaselineMinutes = 30 // "평소" 를 계산할 구간 (최근 1분 제외)
	SpikeMin        = 10 // 최근 1분이 이 이상이어야 급증 후보 (소량 노이즈 무시)
	SpikeFactor     = 3  // 평소 분당 평균의 몇 배 이상이면 급증
)

func ready() bool { return DB != nil }

// ListPosts 는 전체 글 목록을 돌려준다.
func ListPosts() ([]Post, error) {
	if !ready() {
		return nil, ErrNoDB
	}
	rows, err := DB.Query(`SELECT id, title, owner, view_count FROM posts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Post
	for rows.Next() {
		var p Post
		if err := rows.Scan(&p.ID, &p.Title, &p.Owner, &p.ViewCount); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPost 는 글 한 건을 돌려준다.
func GetPost(id int) (*Post, error) {
	if !ready() {
		return nil, ErrNoDB
	}
	var p Post
	err := DB.QueryRow(
		`SELECT id, title, content, owner, view_count FROM posts WHERE id = ?`, id,
	).Scan(&p.ID, &p.Title, &p.Content, &p.Owner, &p.ViewCount)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// IncrementView 는 조회수를 원자적으로 1 증가시킨다 (동시 요청 경쟁조건 방지).
func IncrementView(id int) error {
	if !ready() {
		return ErrNoDB
	}
	_, err := DB.Exec(`UPDATE posts SET view_count = view_count + 1 WHERE id = ?`, id)
	return err
}

// InsertViewEvent 는 조회 시도 1건을 기록한다.
func InsertViewEvent(e ViewEvent) error {
	if !ready() {
		return ErrNoDB
	}
	_, err := DB.Exec(
		`INSERT INTO view_events (post_id, created_at, ip, token, user_agent, reason, counted)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.PostID, e.CreatedAt, e.IP, e.Token, e.UserAgent, e.Reason, boolToInt(e.Counted),
	)
	return err
}

// Dashboard 는 게시판별 집계와 미반영 사유 분포를 돌려준다.
func Dashboard() ([]PostStats, error) {
	if !ready() {
		return nil, ErrNoDB
	}

	rows, err := DB.Query(`
		SELECT p.id, p.title, p.owner, p.view_count,
		       COUNT(e.id)                                   AS total,
		       COALESCE(SUM(e.counted = 1), 0)               AS reflected,
		       COALESCE(SUM(e.counted = 0), 0)               AS rejected,
		       COALESCE(SUM(e.counted = 1 AND e.scrubbed = 1), 0) AS scrubbed
		FROM posts p
		LEFT JOIN view_events e ON e.post_id = p.id
		GROUP BY p.id, p.title, p.owner, p.view_count
		ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make([]PostStats, 0)
	index := map[int]int{}
	for rows.Next() {
		var s PostStats
		if err := rows.Scan(&s.ID, &s.Title, &s.Owner, &s.ViewCount, &s.Total, &s.Reflected, &s.Rejected, &s.Scrubbed); err != nil {
			return nil, err
		}
		s.Reasons = map[string]int{}
		s.ScrubReasons = map[string]int{}
		index[s.ID] = len(stats)
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 미반영 사유별 분포(인라인에서 걸러진 것)
	rrows, err := DB.Query(`
		SELECT post_id, reason, COUNT(*)
		FROM view_events
		WHERE counted = 0
		GROUP BY post_id, reason`)
	if err != nil {
		return nil, err
	}
	defer rrows.Close()
	for rrows.Next() {
		var pid, cnt int
		var reason string
		if err := rrows.Scan(&pid, &reason, &cnt); err != nil {
			return nil, err
		}
		if i, ok := index[pid]; ok {
			stats[i].Reasons[reason] = cnt
		}
	}
	if err := rrows.Err(); err != nil {
		return nil, err
	}

	// 소급 차감(스크럽) 사유별 분포
	srows, err := DB.Query(`
		SELECT post_id, scrub_reason, COUNT(*)
		FROM view_events
		WHERE counted = 1 AND scrubbed = 1
		GROUP BY post_id, scrub_reason`)
	if err != nil {
		return nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var pid, cnt int
		var reason string
		if err := srows.Scan(&pid, &reason, &cnt); err != nil {
			return nil, err
		}
		if i, ok := index[pid]; ok {
			stats[i].ScrubReasons[reason] = cnt
		}
	}
	if err := srows.Err(); err != nil {
		return nil, err
	}

	if err := fillTrend(stats, index); err != nil {
		return nil, err
	}
	return stats, nil
}

// fillTrend 는 글별 분당 시도 수와 급증 여부를 채운다.
// 기준 시각은 DB NOW() 대신 앱 시각을 넘긴다(INSERT 때와 같은 시간대로 직렬화되도록).
func fillTrend(stats []PostStats, index map[int]int) error {
	window := BaselineMinutes + 1
	now := time.Now()
	rows, err := DB.Query(`
		SELECT post_id, TIMESTAMPDIFF(MINUTE, created_at, ?) AS ago, COUNT(*)
		FROM view_events
		WHERE created_at > ?
		GROUP BY post_id, ago`,
		now, now.Add(-time.Duration(window)*time.Minute))
	if err != nil {
		return err
	}
	defer rows.Close()

	// perMinute[i][ago] : ago 분 전(0 = 최근 1분)의 시도 수
	perMinute := make([][]int, len(stats))
	for i := range perMinute {
		perMinute[i] = make([]int, window)
	}
	for rows.Next() {
		var pid, ago, cnt int
		if err := rows.Scan(&pid, &ago, &cnt); err != nil {
			return err
		}
		if i, ok := index[pid]; ok && ago >= 0 && ago < window {
			perMinute[i][ago] += cnt
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for i := range stats {
		m := perMinute[i]
		sum := 0
		for _, c := range m[1:] {
			sum += c
		}
		s := &stats[i]
		s.PerMin = m[0]
		s.Baseline = float64(sum) / float64(BaselineMinutes)
		s.Spike = s.PerMin >= SpikeMin && float64(s.PerMin) >= SpikeFactor*s.Baseline
		s.Trend = make([]int, TrendMinutes)
		for k := 0; k < TrendMinutes; k++ {
			s.Trend[k] = m[TrendMinutes-1-k]
		}
	}
	return nil
}

// ResetStats 는 모든 조회수와 이벤트 기록을 초기화한다 (레벨 바꿀 때 사용).
func ResetStats() error {
	if !ready() {
		return ErrNoDB
	}
	if _, err := DB.Exec(`DELETE FROM view_events`); err != nil {
		return err
	}
	_, err := DB.Exec(`UPDATE posts SET view_count = 0`)
	return err
}

// ScrubCandidate 는 사후 스크러빙 검사 대상 이벤트 1건(인라인 통과 + 아직 미차감).
type ScrubCandidate struct {
	ID        int64
	PostID    int
	IP        string
	UserAgent string
	CreatedAt time.Time
}

// CountedSince 는 window 구간 안에서 "인라인 통과했지만 아직 스크럽되지 않은" 이벤트를 돌려준다.
// 스크러버가 집계 관점으로 재검사할 후보다.
func CountedSince(window time.Duration) ([]ScrubCandidate, error) {
	if !ready() {
		return nil, ErrNoDB
	}
	cutoff := time.Now().Add(-window)
	rows, err := DB.Query(`
		SELECT id, post_id, ip, user_agent, created_at
		FROM view_events
		WHERE counted = 1 AND scrubbed = 0 AND created_at > ?
		ORDER BY post_id`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScrubCandidate
	for rows.Next() {
		var c ScrubCandidate
		if err := rows.Scan(&c.ID, &c.PostID, &c.IP, &c.UserAgent, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ScrubEvents 는 한 글의 이벤트 묶음을 소급 차감한다(트랜잭션).
// 아직 scrubbed=0 인 것만 표시하고, 실제로 바뀐 수만큼 posts.view_count 를 줄인다(0 미만 방지).
// 반환값은 실제로 차감된 건수.
func ScrubEvents(postID int, ids []int64, reason string) (int, error) {
	if !ready() {
		return 0, ErrNoDB
	}
	if len(ids) == 0 {
		return 0, nil
	}
	ph := make([]string, len(ids))
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, reason)
	for i, id := range ids {
		ph[i] = "?"
		args = append(args, id)
	}

	tx, err := DB.Begin()
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(
		"UPDATE view_events SET scrubbed = 1, scrub_reason = ? "+
			"WHERE scrubbed = 0 AND id IN ("+strings.Join(ph, ",")+")", args...)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		if _, err := tx.Exec(
			`UPDATE posts SET view_count = GREATEST(view_count - ?, 0) WHERE id = ?`,
			affected, postID); err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(affected), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
