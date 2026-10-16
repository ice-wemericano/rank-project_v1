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

async function refresh() {
    try {
        const res = await fetch("/api/dashboard");
        const data = await res.json();
        if (!res.ok) {
            bodyEl.innerHTML = `<tr><td colspan="8">${escape(data.error || "오류")}</td></tr>`;
            return;
        }
        levelSel.value = String(data.default_level);
        const posts = data.posts || [];
        if (posts.length === 0) {
            bodyEl.innerHTML = `<tr><td colspan="8">데이터 없음 (db/schema.sql 실행 필요)</td></tr>`;
            return;
        }
        bodyEl.innerHTML = posts.map(p => `
            <tr>
                <td>${escape(p.title)}</td>
                <td>${escape(p.owner)}</td>
                <td>${levelDropdown(p.id, p.level)}</td>
                <td class="num reflected">${p.view_count}</td>
                <td class="num total">${p.total}</td>
                <td class="num reflected">${p.reflected}</td>
                <td class="num rejected">${p.rejected}</td>
                <td>${reasonTags(p.reasons)}</td>
            </tr>`).join("");
    } catch (e) {
        bodyEl.innerHTML = `<tr><td colspan="8">서버 응답 없음</td></tr>`;
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
