
const params = new URLSearchParams(location.search);
const id = params.get("id");

function escape(s) {
    return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

const LEVEL_NAMES = ["Lv0 없음", "Lv1 쿠키", "Lv2 +IP", "Lv3 +속도", "Lv4 +봇", "Lv5 +열람증명"];
function levelName(l) { return LEVEL_NAMES[l] || ("Lv" + l); }

async function run() {
    const titleEl = document.getElementById("title");
    const metaEl = document.getElementById("meta");
    const contentEl = document.getElementById("content");
    const statusEl = document.getElementById("status");

    if (!id) { titleEl.textContent = "잘못된 접근 (id 없음)"; return; }

    // 1) 글 열기 + 열람증명 토큰 발급
    let open;
    try {
        const res = await fetch(`/api/posts/open?id=${id}`);
        open = await res.json();
        if (!res.ok) { titleEl.textContent = open.error || "글을 열 수 없습니다"; return; }
    } catch (e) { titleEl.textContent = "서버 응답 없음"; return; }

    const post = open.post;
    titleEl.textContent = post.title;
    metaEl.innerHTML = `작성자 ${escape(post.owner)} · 조회수 <span class="views" id="vc">${post.view_count}</span>`
        + ` · 방어 <span class="lv lv${post.level}">${levelName(post.level)}</span>`;
    contentEl.textContent = post.content;

    const dwell = open.min_dwell_ms || 0;
    if (dwell > 0) statusEl.textContent = `열람증명: ${(dwell / 1000)}초 머문 뒤 조회수 반영을 시도합니다…`;

    // 2) 최소 체류 시간만큼 기다린 뒤 조회수 증가 시도
    setTimeout(async () => {
        try {
            const res = await fetch(`/api/posts/view?id=${id}&pt=${encodeURIComponent(open.proof_token)}`);
            const r = await res.json();
            if (r.counted) {
                statusEl.innerHTML = `<span class="ok">✔ 조회수에 반영되었습니다.</span> (방어 Lv${r.level})`;
                const vc = document.getElementById("vc");
                if (vc) vc.textContent = Number(vc.textContent) + 1;
            } else {
                statusEl.innerHTML = `<span class="no">✖ 반영되지 않았습니다 — 사유: ${r.reason}</span> (방어 Lv${r.level})`;
            }
        } catch (e) {
            statusEl.textContent = "조회수 반영 요청 실패";
        }
    }, dwell);
}

run();
