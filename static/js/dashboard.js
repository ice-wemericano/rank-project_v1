const bodyEl = document.getElementById("body");
const levelSel = document.getElementById("level");
const autoChk = document.getElementById("auto");

const LEVELS = [
    [0, "Lv0 없음"], [1, "Lv1 쿠키"], [2, "Lv2 +IP"],
    [3, "Lv3 +실IP·속도"], [4, "Lv4 +봇"], [5, "Lv5 +열람증명"],
    [6, "Lv6 +사후스크럽"], [7, "Lv7 +디바이스증명"], [8, "Lv8 +이상탐지"],
    [9, "Lv9 +불투명응답"], [10, "Lv10 +평판·그래프군집"],
];

function escape(s) {
    return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function reasonTags(reasons) {
    const keys = Object.keys(reasons || {});
    if (keys.length === 0) return '<span class="reasons">—</span>';
    return keys.map(k => `<span class="tag">${escape(k)} ${reasons[k]}</span>`).join("");
}

// 소급 차감(스크럽) 셀: 차감 수 + 사유별 태그.
function scrubCell(p) {
    const n = p.scrubbed ?? 0;
    const tags = reasonTags(p.scrub_reasons);
    const num = n > 0 ? `<span class="scrubbed">−${n}</span> ` : "—";
    return `${num}${n > 0 ? tags : ""}`;
}

function levelDropdown(postId, current) {
    const opts = LEVELS.map(([v, label]) =>
        `<option value="${v}" ${v === current ? "selected" : ""}>${label}</option>`).join("");
    return `<select class="rowlevel" data-id="${postId}">${opts}</select>`;
}

// 분당 시도 수 막대그래프 (오래된 것 → 최근, 마지막 막대가 최근 1분)
function sparkline(trend) {
    const t = trend || [];
    const w = 4, gap = 1, h = 24;
    const max = Math.max(1, ...t);
    const bars = t.map((v, i) => {
        const bh = v === 0 ? 1 : Math.max(2, Math.round((v / max) * h));
        const cls = i === t.length - 1 ? ' class="now"' : "";
        return `<rect${cls} x="${i * (w + gap)}" y="${h - bh}" width="${w}" height="${bh}" rx="1"><title>${t.length - 1 - i}분 전: ${v}</title></rect>`;
    }).join("");
    return `<svg class="spark" width="${t.length * (w + gap)}" height="${h}">${bars}</svg>`;
}

function rateCell(p) {
    const badge = p.spike ? '<span class="badge">급증</span>' : "";
    return `<div class="rate">${sparkline(p.trend)}<span><span class="n">${p.per_min ?? 0}</span>${badge}`
        + `<span class="base">평소 ${(p.baseline ?? 0).toFixed(1)}/분</span></span></div>`;
}

function renderAlert(posts) {
    const el = document.getElementById("alert");
    const hot = posts.filter(p => p.spike);
    el.classList.toggle("on", hot.length > 0);
    el.innerHTML = hot.length === 0 ? "" : "⚠ 급증 감지 — " + hot.map(p =>
        `${escape(p.title)} (${escape(p.owner)}) 분당 ${p.per_min}건, 평소 ${p.baseline.toFixed(1)}건`).join(" · ");
}

// 렌더링은 데이터 갱신과 분리한다. 드롭다운(<select>)은 행을 처음 만들 때 한 번만 생성하고,
// 이후 2초 주기에는 숫자 셀만 제자리 갱신한다 → 레벨을 바꾸는 도중에 드롭다운이 다시 그려져
// 선택이 되돌아가는 문제를 없앤다.
let renderedPids = []; // 현재 DOM 에 그려진 글 id 순서

function buildRow(p) {
    const tr = document.createElement("tr");
    tr.dataset.pid = p.id;
    tr.innerHTML =
        `<td class="c-title"></td>`
        + `<td class="c-owner"></td>`
        + `<td class="c-level">${levelDropdown(p.id, p.level)}</td>` // select 는 여기서 한 번만 생성
        + `<td class="num c-rate"></td>`
        + `<td class="num reflected c-view"></td>`
        + `<td class="num total c-total"></td>`
        + `<td class="num reflected c-reflected"></td>`
        + `<td class="num rejected c-rejected"></td>`
        + `<td class="c-reasons"></td>`
        + `<td class="num c-scrub"></td>`;
    return tr;
}

function updateRow(tr, p) {
    tr.classList.toggle("spiking", !!p.spike);
    tr.querySelector(".c-title").textContent = p.title;   // textContent → XSS 안전
    tr.querySelector(".c-owner").textContent = p.owner;
    tr.querySelector(".c-rate").innerHTML = rateCell(p);
    tr.querySelector(".c-view").textContent = p.view_count;
    tr.querySelector(".c-total").textContent = p.total;
    tr.querySelector(".c-reflected").textContent = p.reflected;
    tr.querySelector(".c-rejected").textContent = p.rejected;
    tr.querySelector(".c-reasons").innerHTML = reasonTags(p.reasons);
    tr.querySelector(".c-scrub").innerHTML = scrubCell(p);
    // 레벨 드롭다운: 사용자가 조작 중(포커스)이 아닐 때만 서버 값으로 맞춘다(선택을 덮어쓰지 않음).
    const sel = tr.querySelector(".rowlevel");
    if (sel && document.activeElement !== sel) sel.value = String(p.level);
}

function render(posts) {
    const pids = posts.map(p => p.id);
    const same = pids.length === renderedPids.length && pids.every((v, i) => v === renderedPids[i]);
    if (!same) {
        // 글 목록 구성이 바뀐 경우에만 전체 재구성(그 외엔 드롭다운을 보존).
        bodyEl.innerHTML = "";
        posts.forEach(p => bodyEl.appendChild(buildRow(p)));
        renderedPids = pids;
    }
    posts.forEach(p => {
        const tr = bodyEl.querySelector(`tr[data-pid="${p.id}"]`);
        if (tr) updateRow(tr, p);
    });
}

function showMessage(msg) {
    bodyEl.innerHTML = `<tr><td colspan="10">${escape(msg)}</td></tr>`;
    renderedPids = []; // 다음 정상 응답 때 전체 재구성되도록
}

async function refresh() {
    try {
        const res = await fetch("/api/dashboard");
        const data = await res.json();
        if (!res.ok) {
            showMessage(data.error || "오류");
            return;
        }
        // 기본 레벨 셀렉터도 조작 중이 아닐 때만 갱신.
        if (document.activeElement !== levelSel) levelSel.value = String(data.default_level);
        const posts = data.posts || [];
        if (posts.length === 0) {
            showMessage("데이터 없음 (db/schema.sql 실행 필요)");
            return;
        }
        renderAlert(posts);
        render(posts);
    } catch (e) {
        showMessage("서버 응답 없음");
    }
}

bodyEl.addEventListener("change", async (e) => {
    const sel = e.target.closest(".rowlevel");
    if (!sel) return;
    await fetch(`/api/admin/level?id=${sel.dataset.id}&level=${sel.value}`, { method: "POST" });
    refresh();
});

document.getElementById("apply").addEventListener("click", async () => {
    await fetch(`/api/admin/level?level=${levelSel.value}`, { method: "POST" });
    refresh();
});

document.getElementById("reset").addEventListener("click", async () => {
    if (!confirm("모든 조회수와 요청 기록을 초기화합니다. 계속할까요?")) return;
    await fetch("/api/admin/reset", { method: "POST" });
    refresh();
});

// 렌더링이 드롭다운을 보존하므로 자동 새로고침은 그냥 돌려도 안전하다
// (updateRow 가 포커스 중인 셀렉터는 건드리지 않는다).
let timer = setInterval(() => {
    if (autoChk.checked) refresh();
}, 2000);
refresh();
