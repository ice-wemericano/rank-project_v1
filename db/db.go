package db

import (
	"database/sql"
	"fmt"
	"os"

	"rank-project_v1/logs"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func Init() error {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	// timeout/readTimeout/writeTimeout 을 짧게 둬서 NAS 다운 시 요청이 오래 매달리지 않게 한다.
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local&timeout=3s&readTimeout=5s&writeTimeout=5s",
		user,
		password,
		host,
		port,
		dbName,
	)

	var err error

	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		return err
	}

	if err = DB.Ping(); err != nil {
		return err
	}

	logs.Log("DB", "DB connected")

	// Lv6 사후 스크러빙용 컬럼이 없으면 추가한다(스키마 파일 없이도 동작하도록).
	if err := migrate(); err != nil {
		logs.Log("DB", "[WARN] 마이그레이션 실패(스크럽 컬럼) - 계속 진행: "+err.Error())
	}

	return nil
}

// migrate 는 view_events 에 Lv6 스크러빙 컬럼(scrubbed, scrub_reason)이 없으면 추가한다.
// view_events 테이블 자체가 없으면(축소 모드) 조용히 건너뛴다.
func migrate() error {
	var exists int
	err := DB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = DATABASE() AND table_name = 'view_events'`).Scan(&exists)
	if err != nil || exists == 0 {
		return err
	}
	cols := map[string]string{
		"scrubbed":     "TINYINT(1) NOT NULL DEFAULT 0",
		"scrub_reason": "VARCHAR(32) NOT NULL DEFAULT ''",
	}
	for name, def := range cols {
		var has int
		if err := DB.QueryRow(`
			SELECT COUNT(*) FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = 'view_events' AND column_name = ?`,
			name).Scan(&has); err != nil {
			return err
		}
		if has == 0 {
			if _, err := DB.Exec("ALTER TABLE view_events ADD COLUMN " + name + " " + def); err != nil {
				return err
			}
			logs.Log("DB", "마이그레이션: view_events."+name+" 추가")
		}
	}
	return nil
}
