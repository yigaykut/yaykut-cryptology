"use strict";

/* ═══════════════════════════════════════════════════════════════
   Background: a dome grid, collision trails, a fractal silhouette and a
   perspective floor. All generated at runtime; none of it is an image file.
   ═══════════════════════════════════════════════════════════════ */

const backdrop = document.getElementById("backdrop");
const cx2 = backdrop.getContext("2d", { alpha: false });

const REDUCED_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;

let W = 0, H = 0, HORIZON = 0, CENTRE = 0, DPR = 1;
let layerTrace = null;      // pre-rendered trails (offscreen)
let layerDome = null;   // pre-rendered dome
let layerSilhouette = null;  // mountains plus a fractal tree

const random = (a, b) => a + Math.random() * (b - a);

/* --- dome: latitude and longitude arcs --- */
function makeDome() {
  const c = document.createElement("canvas");
  c.width = W; c.height = H;
  const g = c.getContext("2d");

  const rx = W * 0.78, ry = H * 0.92;
  g.lineWidth = 1;

  // longitudes: ellipses through a shared apex
  for (let j = -9; j <= 9; j++) {
    const t = j / 9;
    g.strokeStyle = `rgba(120,150,185,${0.13 - Math.abs(t) * 0.06})`;
    g.beginPath();
    g.ellipse(CENTRE, HORIZON, Math.abs(rx * t) + 0.5, ry, 0, Math.PI, Math.PI * 2);
    g.stroke();
  }

  // enlemler
  for (let k = 1; k <= 11; k++) {
    const t = k / 11;
    g.strokeStyle = `rgba(120,150,185,${0.14 * (1 - t * 0.55)})`;
    g.beginPath();
    g.ellipse(CENTRE, HORIZON, rx * t, ry * t, 0, Math.PI, Math.PI * 2);
    g.stroke();
  }

  // sacred geometry: a bundle of circles on a hex lattice
  const r = Math.min(W, H) * 0.085;
  g.strokeStyle = "rgba(217,43,43,.075)";
  g.lineWidth = 1;
  const oy = HORIZON - H * 0.42;
  for (let a = -3; a <= 3; a++) {
    for (let b = -3; b <= 3; b++) {
      const x = CENTRE + (a + b * 0.5) * r * 1.732;
      const y = oy + b * r * 1.5;
      if (Math.hypot(x - CENTRE, y - oy) > r * 5.2) continue;
      g.beginPath();
      g.arc(x, y, r, 0, Math.PI * 2);
      g.stroke();
    }
  }
  return c;
}

/* --- collision trails: curved paths plus Archimedean spirals --- */
function makeTraces() {
  const c = document.createElement("canvas");
  c.width = W; c.height = H;
  const g = c.getContext("2d");
  g.lineCap = "round";

  const ox = CENTRE, oy = HORIZON - H * 0.44;
  const range = Math.min(W, H);

  for (let i = 0; i < 170; i++) {
    const a0 = random(0, Math.PI * 2);
    const r0 = random(0, range * 0.05);
    let x = ox + Math.cos(a0) * r0;
    let y = oy + Math.sin(a0) * r0;

    let ang = a0 + random(-0.5, 0.5);
    const len = random(range * 0.08, range * 0.92);
    const arc = random(-0.032, 0.032);
    const count = 60;
    const step = len / count;

    g.beginPath();
    g.moveTo(x, y);
    for (let s = 0; s < count; s++) {
      ang += arc;
      x += Math.cos(ang) * step;
      y += Math.sin(ang) * step;
      g.lineTo(x, y);
    }

    // 22 percent chance of a spiral at the end (r = a + b*theta)
    if (Math.random() < 0.22) {
      let sr = 1.4, sa = ang;
      const dir = Math.random() < 0.5 ? 1 : -1;
      for (let k = 0; k < 80; k++) {
        sa += 0.32 * dir;
        sr += 0.42;
        g.lineTo(x + Math.cos(sa) * sr, y + Math.sin(sa) * sr);
      }
    }

    const bright = Math.random() < 0.16;
    g.lineWidth = bright ? random(1.1, 1.8) : random(0.35, 0.9);
    g.strokeStyle = bright
      ? `rgba(255,90,80,${random(0.45, 0.75)})`
      : `rgba(206,40,40,${random(0.13, 0.4)})`;
    if (bright) { g.shadowBlur = 10; g.shadowColor = "rgba(255,74,72,.85)"; }
    g.stroke();
    g.shadowBlur = 0;
  }

  // core of the collision point
  const fetch = g.createRadialGradient(ox, oy, 0, ox, oy, range * 0.2);
  fetch.addColorStop(0, "rgba(255,120,90,.16)");
  fetch.addColorStop(1, "rgba(255,60,60,0)");
  g.fillStyle = fetch;
  g.fillRect(ox - range * 0.2, oy - range * 0.2, range * 0.4, range * 0.4);

  return c;
}

/* --- silhouette: mountain profile plus a recursive tree --- */
function makeSilhouette() {
  const c = document.createElement("canvas");
  c.width = W; c.height = H;
  const g = c.getContext("2d");
  g.fillStyle = "#000";
  g.strokeStyle = "#000";

  // mountains
  g.beginPath();
  g.moveTo(0, H);
  g.lineTo(0, HORIZON - H * 0.02);
  let x = 0;
  while (x < W) {
    const w = random(W * 0.05, W * 0.16);
    const h = random(H * 0.015, H * 0.09);
    g.lineTo(x + w * 0.5, HORIZON - h);
    g.lineTo(x + w, HORIZON - random(0, H * 0.02));
    x += w;
  }
  g.lineTo(W, H);
  g.closePath();
  g.fill();

  // fractal tree: branch ratio 0.76, angle +/-0.34 rad
  function branch(x, y, ang, len, depth) {
    if (depth === 0 || len < 2) return;
    const x2 = x + Math.cos(ang) * len;
    const y2 = y + Math.sin(ang) * len;
    g.lineWidth = Math.max(0.6, depth * 0.85);
    g.beginPath();
    g.moveTo(x, y);
    g.lineTo(x2, y2);
    g.stroke();
    branch(x2, y2, ang - random(0.24, 0.46), len * 0.76, depth - 1);
    branch(x2, y2, ang + random(0.24, 0.46), len * 0.76, depth - 1);
    if (Math.random() < 0.28) branch(x2, y2, ang + random(-0.2, 0.2), len * 0.58, depth - 1);
  }
  branch(CENTRE, HORIZON + H * 0.02, -Math.PI / 2, H * 0.075, 9);

  return c;
}

function resize() {
  DPR = Math.min(devicePixelRatio || 1, 2);
  W = innerWidth; H = innerHeight;
  backdrop.width = W * DPR; backdrop.height = H * DPR;
  backdrop.style.width = W + "px"; backdrop.style.height = H + "px";
  cx2.setTransform(DPR, 0, 0, DPR, 0, 0);

  HORIZON = H * 0.64;
  CENTRE = W * 0.5;

  layerDome = makeDome();
  layerTrace = makeTraces();
  layerSilhouette = makeSilhouette();
}

function draw(t) {
  // sky
  const sky = cx2.createLinearGradient(0, 0, 0, HORIZON);
  sky.addColorStop(0, "#0a0409");
  sky.addColorStop(0.55, "#1d0810");
  sky.addColorStop(1, "#3d1018");
  cx2.fillStyle = sky;
  cx2.fillRect(0, 0, W, HORIZON + 2);

  // floor gap
  cx2.fillStyle = "#05060a";
  cx2.fillRect(0, HORIZON, W, H - HORIZON);

  cx2.drawImage(layerDome, 0, 0, W, H);

  // trails: slow oscillation
  const breathe = REDUCED_MOTION ? 1 : 0.82 + 0.18 * Math.sin(t * 0.0004);
  cx2.save();
  cx2.globalAlpha = breathe;
  if (!REDUCED_MOTION) {
    cx2.translate(CENTRE, HORIZON - H * 0.44);
    cx2.rotate(Math.sin(t * 0.00006) * 0.016);
    cx2.translate(-CENTRE, -(HORIZON - H * 0.44));
  }
  cx2.drawImage(layerTrace, 0, 0, W, H);
  cx2.restore();

  // ufuk koru
  const blind = cx2.createRadialGradient(CENTRE, HORIZON, 0, CENTRE, HORIZON, W * 0.55);
  blind.addColorStop(0, "rgba(255,106,61,.34)");
  blind.addColorStop(0.4, "rgba(217,43,43,.12)");
  blind.addColorStop(1, "rgba(217,43,43,0)");
  cx2.fillStyle = blind;
  cx2.fillRect(0, HORIZON - H * 0.3, W, H * 0.35);

  cx2.drawImage(layerSilhouette, 0, 0, W, H);

  // perspektif ground
  const shift = REDUCED_MOTION ? 0 : (t * 0.00007) % 1;
  cx2.lineWidth = 1;

  for (let k = 0; k < 30; k++) {
    const z = k + shift;
    const y = HORIZON + (H - HORIZON) * (1 - 1 / (1 + z * 0.30));
    if (y > H) break;
    const near = (y - HORIZON) / (H - HORIZON);
    cx2.strokeStyle = `rgba(93,143,185,${0.06 + near * 0.30})`;
    cx2.beginPath();
    cx2.moveTo(0, y);
    cx2.lineTo(W, y);
    cx2.stroke();
  }

  for (let i = -26; i <= 26; i++) {
    cx2.strokeStyle = `rgba(93,143,185,${0.24 - Math.abs(i) * 0.006})`;
    cx2.beginPath();
    cx2.moveTo(CENTRE, HORIZON);
    cx2.lineTo(CENTRE + i * W * 0.085, H);
    cx2.stroke();
  }

  // horizon line
  cx2.strokeStyle = "rgba(255,106,61,.5)";
  cx2.beginPath();
  cx2.moveTo(0, HORIZON);
  cx2.lineTo(W, HORIZON);
  cx2.stroke();
}

let firstFrame = 0;
function loop(t) {
  draw(t - firstFrame);
  requestAnimationFrame(loop);
}

addEventListener("resize", () => { resize(); if (REDUCED_MOTION) draw(0); });
resize();
if (REDUCED_MOTION) draw(0); else requestAnimationFrame((t) => { firstFrame = t; loop(t); });


/* ═══════════════════════════════════════════════════════════════
   UYGULAMA
   ═══════════════════════════════════════════════════════════════ */

const $ = (id) => document.getElementById(id);

const el = {
  key: $("key"), keyGenerate: $("key-generate"), keyStatus: $("key-status"),
  plain: $("plain"), cipher: $("cipher"), encrypt: $("encrypt"),
  inputCipher: $("input-cipher"), decrypted: $("decrypted"), decrypt: $("decrypt"),
  measureChars: $("measure-chars"), measureBytes: $("measure-bytes"),
  fillBar: $("fill-bar"), decryptMeasure: $("decrypt-measure"),
  decryptExpected: $("decrypt-expected"), decryptBar: $("decrypt-bar"),
  warning: $("warning"),
  vNonce: $("v-nonce"), vSelector: $("v-selector"), vTag: $("v-tag"),
};

let FIXED = { capacity: 1024, totalBytes: 1339 };

const byteLength = (s) => new TextEncoder().encode(s).length;

function warn(message) {
  if (!message) { el.warning.classList.add("hidden"); return; }
  el.warning.textContent = message;
  el.warning.classList.remove("hidden");
}

async function call(uc, body) {
  const y = await fetch(uc, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return y.json();
}

/* ─── key ─── */

function checkKey() {
  const v = el.key.value.trim();
  const valid = /^[0-9a-fA-F]+$/.test(v) && v.length >= 32 && v.length % 2 === 0;
  el.keyStatus.textContent = v ? `${v.length / 2 | 0} B` : "—";
  el.keyStatus.className = "badge " + (v ? (valid ? "good" : "bad") : "");
  el.encrypt.disabled = !valid;
  el.decrypt.disabled = !valid;
  return valid;
}

el.key.addEventListener("input", checkKey);

el.keyGenerate.addEventListener("click", async () => {
  const y = await (await fetch("/api/key")).json();
  el.key.value = y.key;
  checkKey();
  warn("");
});

/* --- measurements --- */

function measurePlain() {
  const n = byteLength(el.plain.value);
  const ratio = Math.min(1, n / FIXED.capacity);
  el.measureChars.textContent = `${el.plain.value.length} characters`;
  el.measureBytes.textContent = `${n} / ${FIXED.capacity} bytes`;
  const overflow = n > FIXED.capacity;
  el.measureBytes.classList.toggle("overflow", overflow);
  el.fillBar.style.width = (ratio * 100) + "%";
  el.fillBar.classList.toggle("overflow", overflow);
}

function measureCipher() {
  const hex = el.inputCipher.value.replace(/\s+/g, "");
  const n = Math.floor(hex.length / 2);
  el.decryptMeasure.textContent = `${n} bytes`;
  const complete = n === FIXED.totalBytes;
  el.decryptMeasure.classList.toggle("overflow", n > 0 && !complete);
  el.decryptBar.style.width = Math.min(100, n / FIXED.totalBytes * 100) + "%";
  el.decryptBar.classList.toggle("overflow", n > FIXED.totalBytes);
}

el.plain.addEventListener("input", measurePlain);
el.inputCipher.addEventListener("input", measureCipher);

/* --- wire strip --- */

function showRegions(b) {
  if (!b) return;
  el.vNonce.textContent = b.nonce;
  el.vSelector.textContent = b.selector;
  el.vTag.textContent = b.tag;
  document.querySelectorAll(".block").forEach((n) => {
    n.classList.add("flash");
    setTimeout(() => n.classList.remove("flash"), 520);
  });
}

/* --- operations --- */

el.encrypt.addEventListener("click", async () => {
  warn("");
  const text = el.plain.value;
  if (!text) { warn("plaintext is empty"); return; }

  el.encrypt.disabled = true;
  const y = await call("/api/encrypt", { text, key: el.key.value.trim() });
  el.encrypt.disabled = false;

  if (!y.ok) { warn(y.error); el.cipher.value = ""; return; }
  el.cipher.value = y.blob;
  showRegions(y.regions);
});

el.decrypt.addEventListener("click", async () => {
  warn("");
  const blob = el.inputCipher.value.replace(/\s+/g, "");
  if (!blob) { warn("ciphertext is empty"); return; }

  el.decrypt.disabled = true;
  const y = await call("/api/decrypt", { blob, key: el.key.value.trim() });
  el.decrypt.disabled = false;

  if (!y.ok) { warn(y.error); el.decrypted.value = ""; return; }
  el.decrypted.value = y.text;
  showRegions(y.regions);
});

$("transfer").addEventListener("click", () => {
  el.inputCipher.value = el.cipher.value;
  measureCipher();
  el.inputCipher.scrollIntoView({ behavior: REDUCED_MOTION ? "auto" : "smooth", block: "center" });
});

function copier(buttonId, field) {
  $(buttonId).addEventListener("click", async () => {
    if (!field.value) return;
    try { await navigator.clipboard.writeText(field.value); } catch { field.select(); return; }
    const d = $(buttonId), old = d.textContent;
    d.textContent = "COPIED";
    setTimeout(() => { d.textContent = old; }, 1100);
  });
}
copier("copy-cipher", el.cipher);
copier("copy-decrypted", el.decrypted);

$("glossary-open").addEventListener("click", () => {
  const g = $("glossary-body");
  const collapsed = g.classList.toggle("collapsed");
  $("glossary-open").textContent = collapsed ? "SHOW" : "HIDE";
});

/* --- startup --- */

(async function start() {
  try {
    FIXED = await (await fetch("/api/state")).json();
  } catch { warn("could not reach the server"); return; }

  $("wire-total").textContent = `${FIXED.totalBytes} B`;
  $("w-nonce").textContent = `${FIXED.nonceBytes} B`;
  $("w-selector").textContent = `${FIXED.selectorBytes} B`;
  $("w-payload").textContent = `${FIXED.payloadBytes} B`;
  $("w-tag").textContent = `${FIXED.tagBytes} B`;
  $("m-entry-id").textContent = FIXED.entryId;
  $("m-entry-name").textContent = FIXED.entryName;
  $("m-payload-bits").textContent = FIXED.payloadBits;
  $("m-padding-bits").textContent = FIXED.paddingBits;
  $("m-corpus").textContent = FIXED.corpus;
  el.decryptExpected.textContent = `expected ${FIXED.totalBytes}`;

  // corpus formulas come from the server, never hard coded in the UI
  const list = $("cs-list");
  list.innerHTML = "";
  for (const f of (FIXED.samples || [])) {
    const d = document.createElement("div");
    d.className = "cs-item";
    d.innerHTML =
      `<div class="cs-id"></div><div class="cs-name"></div>` +
      `<div class="cs-formula"></div><div class="cs-summary"></div>`;
    d.children[0].textContent = f.id;
    d.children[1].textContent = f.name;
    d.children[2].textContent = f.formula;
    d.children[3].textContent = f.summary;
    list.appendChild(d);
  }

  const y = await (await fetch("/api/key")).json();
  el.key.value = y.key;
  checkKey();
  measurePlain();
  measureCipher();
})();
