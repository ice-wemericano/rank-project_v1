const bodyEl = document.getElementById("body");
const levelSel = document.getElementById("level");
const autoChk = document.getElementById("auto");

const LEVELS = [
    [0, "Lv0 없음"], [1, "Lv1 쿠키"], [2, "Lv2 +IP"],
    [3, "Lv3 +실IP·속도"], [4, "Lv4 +봇"], [5, "Lv5 +열람증명"],
];

function escape(s) {
    return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function reasonTags(reasons) {
    const keys = Object.keys(reasons || {});
    if (keys.length === 0) return '<span class="reasons">—</span>';
    return keys.map(k => `<span class="tag">${escape(k)} ${reasons[k]}</span>`).join("");
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

async function refresh() {
    try {
        const res = await fetch("/api/dashboard");
        const data = await res.json();
        if (!res.ok) {
            bodyEl.innerHTML = `<tr><td colspan="9">${escape(data.error || "오류")}</td></tr>`;
            return;
        }
        levelSel.value = String(data.default_level);
        const posts = data.posts || [];
        if (posts.length === 0) {
            bodyEl.innerHTML = `<tr><td colspan="9">데이터 없음 (db/schema.sql 실행 필요)</td></tr>`;
            return;
        }
        renderAlert(posts);
        bodyEl.innerHTML = posts.map(p => `
            <tr class="${p.spike ? "spiking" : ""}">
                <td>${escape(p.title)}</td>
                <td>${escape(p.owner)}</td>
                <td>${levelDropdown(p.id, p.level)}</td>
                <td class="num">${rateCell(p)}</td>
                <td class="num reflected">${p.view_count}</td>
                <td class="num total">${p.total}</td>
                <td class="num reflected">${p.reflected}</td>
                <td class="num rejected">${p.rejected}</td>
                <td>${reasonTags(p.reasons)}</td>
            </tr>`).join("");
    } catch (e) {
        bodyEl.innerHTML = `<tr><td colspan="9">서버 응답 없음</td></tr>`;
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

let timer = setInterval(() => {
    if (autoChk.checked && !document.activeElement?.classList.contains("rowlevel")) refresh();
}, 2000);
refresh();
