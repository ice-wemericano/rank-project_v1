-- rank-project 스키마 (게시판 + 조회 시도 기록).
--
-- 로컬 실측: deploy/local/docker-compose.yml 이 최초 기동 시 이 파일을 자동 실행한다.
-- NAS(운영)에서는 한 번만 수동 실행한다. 이미 테이블이 있으면 앱이 시작 시
-- scrubbed/scrub_reason 컬럼만 자동 보강(db.migrate)하므로, 이 파일을 다시 돌릴 필요는 없다.

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS posts (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  title      VARCHAR(200)  NOT NULL,
  content    TEXT          NOT NULL,
  owner      VARCHAR(100)  NOT NULL DEFAULT '',
  view_count INT           NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS view_events (
  id           BIGINT AUTO_INCREMENT PRIMARY KEY,
  post_id      INT          NOT NULL,
  created_at   DATETIME     NOT NULL,
  ip           VARCHAR(64)  NOT NULL DEFAULT '',
  token        VARCHAR(64)  NOT NULL DEFAULT '',
  user_agent   VARCHAR(512) NOT NULL DEFAULT '',
  reason       VARCHAR(32)  NOT NULL DEFAULT '',
  counted      TINYINT(1)   NOT NULL DEFAULT 0,
  -- Lv6 사후 스크러빙: 인라인 통과(counted=1) 후 집계로 소급 차감된 건을 표시한다.
  scrubbed     TINYINT(1)   NOT NULL DEFAULT 0,
  scrub_reason VARCHAR(32)  NOT NULL DEFAULT '',
  KEY idx_post_time (post_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 시드 글 (로컬 실측용). 이미 있으면 무시.
INSERT INTO posts (id, title, content, owner, view_count) VALUES
  (1, '첫 번째 글',   '조회수 방어 실습용 글입니다.',       'alice', 0),
  (2, '두 번째 글',   '레벨을 바꿔가며 공격해 보세요.',     'bob',   0),
  (3, '세 번째 글',   '대시보드에서 반영/소급차감을 봅니다.', 'carol', 0)
ON DUPLICATE KEY UPDATE title = VALUES(title);
