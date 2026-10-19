
const params = new URLSearchParams(location.search);
const id = params.get("id");

function escape(s) {
    return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

const LEVEL_NAMES = ["Lv0 없음", "Lv1 쿠키", "Lv2 +IP", "Lv3 +실IP·속도", "Lv4 +봇", "Lv5 +열람증명",
    "Lv6 +사후스크럽", "Lv7 +디바이스증명", "Lv8 +이상탐지", "Lv9 +불투명", "Lv10 +평판·그래프"];
function levelName(l) { return LEVEL_NAMES[l] || ("Lv" + l); }

// ---- Lv7 디바이스 소유증명: 비추출 ECDSA 키로 챌린지(열람증명 nonce)를 서명한다 ----
// 개인키는 WebCrypto 로 만들어 IndexedDB 에 보관(비추출 → 복제·공유 불가). crypto.subtle 은
// 보안 컨텍스트(https 또는 localhost)에서만 쓸 수 있다.
function b64url(buf) {
    let s = "";
    for (const x of new Uint8Array(buf)) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function idbOpen() {
    return new Promise((res, rej) => {
        const r = indexedDB.open("rankdev", 1);
        r.onupgradeneeded = () => r.result.createObjectStore("keys");
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
    });
}
function idbGet(db, k) {
    return new Promise((res, rej) => {
        const t = db.transaction("keys", "readonly").objectStore("keys").get(k);
        t.onsuccess = () => res(t.result);
        t.onerror = () => rej(t.error);
    });
}
function idbPut(db, k, v) {
    return new Promise((res, rej) => {
        const t = db.transaction("keys", "readwrite").objectStore("keys").put(v, k);
        t.onsuccess = () => res();
        t.onerror = () => rej(t.error);
    });
}
async function getDeviceKey() {
    const db = await idbOpen();
    let kp = await idbGet(db, "kp");
    if (!kp) {
        // 비추출 개인키(false) + 추출 가능한 공개키(규격상 공개키는 항상 추출 가능).
        kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
        await idbPut(db, "kp", kp);
    }
    return kp;
}
// challenge 를 디바이스 키로 서명하고 공개키를 신원에 등록한 뒤 dsig(base64url)를 돌려준다.
// 보안 컨텍스트가 아니거나 실패하면 "" (→ 서버에서 no_device 로 막힘, 정직한 동작).
async function deviceSign(challenge) {
    if (!(window.crypto && crypto.subtle && window.indexedDB)) return "";
    try {
        const kp = await getDeviceKey();
        const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
        // 공개키를 owner 에 묶어 등록(서버가 dkey 쿠키 발급). view 전에 끝나야 쿠키가 함께 전송된다.
        await fetch(`/api/posts/register-key?pub=${b64url(spki)}`, { method: "POST" });
        const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey,
            new TextEncoder().encode(challenge));
        return b64url(sig);
    } catch (e) {
        return "";
    }
}

// ---- 작업증명(PoW): sha256(challenge + ":" + n) 의 선행 0 비트가 bits 이상인 n 을 찾는다 ----
// crypto.subtle 은 https 에서만 쓸 수 있어서(http://IP:포트 접속 대비) 순수 JS SHA-256 을 쓴다.
const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
const W = new Uint32Array(64);

// ASCII 문자열의 SHA-256 첫 32비트(H0)를 돌려준다. (bits <= 32 판정에는 이걸로 충분)
function sha256First32(str) {
    const len = str.length;
    const nBlocks = ((len + 8) >> 6) + 1;
    const m = new Uint32Array(nBlocks * 16);
    for (let i = 0; i < len; i++) m[i >> 2] |= str.charCodeAt(i) << (24 - (i & 3) * 8);
    m[len >> 2] |= 0x80 << (24 - (len & 3) * 8);
    m[nBlocks * 16 - 1] = len * 8;
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
        h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    for (let b = 0; b < nBlocks; b++) {
        for (let t = 0; t < 16; t++) W[t] = m[b * 16 + t];
        for (let t = 16; t < 64; t++) {
            const x = W[t - 15], y = W[t - 2];
            const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
            const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
            W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
        }
        let a = h0, bb = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let t = 0; t < 64; t++) {
            const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
            const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t]) | 0;
            const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
            const t2 = (S0 + ((a & bb) ^ (a & c) ^ (bb & c))) | 0;
            h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
        }
        h0 = (h0 + a) | 0; h1 = (h1 + bb) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
        h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    return h0 >>> 0;
}

// UI 가 멈추지 않도록 잘게 나눠 푼다.
function solvePoW(challenge, bits) {
    const limit = bits >= 32 ? 0 : (0xffffffff >>> bits);
    return new Promise(resolve => {
        let n = 0;
        const step = () => {
            const end = n + 20000;
            for (; n < end; n++) {
                if (sha256First32(challenge + ":" + n) <= limit) return resolve(String(n));
            }
            setTimeout(step, 0);
        };
        step();
    });
}

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

    const pt = encodeURIComponent(open.proof_token);
    const dwell = open.min_dwell_ms || 0;
    if (dwell > 0) statusEl.textContent = `열람증명: ${(dwell / 1000)}초 머무는 동안 서버에 체류 신호(heartbeat)를 보냅니다…`;

    // 2) 머무는 동안 1초마다 heartbeat 전송 → 서버가 실제 체류시간을 누적한다.
    const beat = () => fetch(`/api/posts/heartbeat?id=${id}&pt=${pt}`).catch(() => {});
    beat();
    const hb = setInterval(beat, 1000);

    // 체류하는 동안 작업증명도 같이 푼다.
    const powP = open.pow_challenge ? solvePoW(open.pow_challenge, open.pow_bits || 0) : Promise.resolve("");

    // 3) 최소 체류시간 + 여유(1.2초) 뒤 조회수 증가 시도
    setTimeout(async () => {
        const pow = await powP;
        clearInterval(hb);
        await beat(); // 마지막 heartbeat 로 잔여 체류 반영

        // Lv7: 디바이스 키로 열람증명 nonce(= pow_challenge)를 서명해 동봉한다.
        let dsig = "";
        if (post.level >= 7) {
            dsig = await deviceSign(open.pow_challenge);
            if (!dsig) statusEl.textContent = "Lv7 디바이스 증명은 https 또는 localhost 에서만 가능합니다.";
        }
        const viewURL = `/api/posts/view?id=${id}&pt=${pt}&pow=${encodeURIComponent(pow)}`
            + (dsig ? `&dsig=${encodeURIComponent(dsig)}` : "");
        try {
            const res = await fetch(viewURL);
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
    }, dwell + 1200);
}

run();
