async function load() {
    const list = document.getElementById("list");
    try {
        const res = await fetch("/api/posts");
        if (!res.ok) {
            const e = await res.json().catch(() => ({}));
            list.innerHTML = `<div class="msg">목록을 불러올 수 없습니다: ${e.error || res.status}</div>`;
            return;
        }
        const posts = await res.json();
        if (!posts || posts.length === 0) {
            list.innerHTML = `<div class="msg">게시글이 없습니다. (DB 초기화 필요: db/schema.sql)</div>`;
            return;
        }
        list.innerHTML = posts.map(p => `
            <a class="card" href="/post.html?id=${p.id}">
                <div class="title">${escape(p.title)}</div>
                <div class="meta">작성자 ${escape(p.owner)} · 조회수 <span class="views">${p.view_count}</span>
                    · 방어 <span class="lv lv${p.level}">${levelName(p.level)}</span></div>
            </a>`).join("");
    } catch (err) {
        list.innerHTML = `<div class="msg">서버 응답 없음: ${err}</div>`;
    }
}

function escape(s) {
    return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

const LEVEL_NAMES = ["Lv0 없음", "Lv1 쿠키", "Lv2 +IP", "Lv3 +실IP·속도", "Lv4 +봇", "Lv5 +열람증명"];
function levelName(l) { return LEVEL_NAMES[l] || ("Lv" + l); }

load();
