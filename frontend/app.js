/* =========================================================
   THEME SWITCHER
   ========================================================= */
const themeBtns = document.querySelectorAll('.theme-btn');

themeBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    document.documentElement.setAttribute('data-theme', btn.dataset.t);
    themeBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  });
});

/* =========================================================
   ELEMENTS
   ========================================================= */
const urlInput       = document.getElementById('urlInput');
const scanBtn        = document.getElementById('scanBtn');
const scanBtnText    = document.getElementById('scanBtnText');
const scanStage      = document.getElementById('scanStage');
const scanLabel      = document.getElementById('scanLabel');

const resultWrap     = document.getElementById('resultWrap');
const resultDivider  = document.getElementById('resultDivider');
const resultCard     = document.getElementById('resultCard');

const statusIcon     = document.getElementById('statusIcon');
const statusLabel    = document.getElementById('statusLabel');
const riskBadge      = document.getElementById('riskBadge');
const resultUrl      = document.getElementById('resultUrl');
const scoreBar       = document.getElementById('scoreBar');
const scoreValue     = document.getElementById('scoreValue');
const resultDetails  = document.getElementById('resultDetails');

const mainCard       = document.getElementById('mainCard');
const shieldCheck    = document.querySelector('.shield-check');

/* =========================================================
   LOADING MESSAGES
   ========================================================= */
const SCAN_MESSAGES = [
  'Analyzing URL structure…',
  'Checking domain reputation…',
  'Scanning for redirect chains…',
  'Running heuristic analysis…',
  'Finalizing risk score…',
];

/* =========================================================
   ICONS
   ========================================================= */
const ICONS = {
  safe: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--safe-color)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
  suspicious: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--suspicious-color)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  dangerous: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--dangerous-color)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
};

/* =========================================================
   STRICT INPUT VALIDATION (NO WORDS ALLOWED)
   ========================================================= */
function isValidClientInput(input) {
  input = input.trim();

  // ❌ block spaces or raw text
  if (input.includes(" ")) return false;

  // must contain dot OR be IP-like
  if (!input.includes(".") && !/^\d+\./.test(input)) return false;

  return true;
}

/* =========================================================
   MAIN SCAN FUNCTION (BACKEND CONNECTED)
   ========================================================= */
async function performScan(url) {
  const scanInterval = startLoadingAnimation();

  try {
    const response = await fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) throw new Error("Backend error");

    const data = await response.json();

    clearInterval(scanInterval);

    renderResult(
      data.url || url,
      data.status?.toLowerCase() || "dangerous",
      data.score ?? 100,
      (data.reasons || []).join(" • ")
    );

  } catch (err) {
    clearInterval(scanInterval);

    renderResult(
      url,
      "dangerous",
      100,
      "Unable to contact backend server or invalid response."
    );

    console.error(err);
  }
}

/* =========================================================
   SCAN BUTTON
   ========================================================= */
function startScan() {
  const raw = urlInput.value.trim();

  // ❌ reject invalid input BEFORE modification
  if (!raw || !isValidClientInput(raw)) {
    shake(urlInput);
    return;
  }

  const url = raw.startsWith('http') ? raw : 'https://' + raw;

  resetUIForScan();
  performScan(url);
}

/* =========================================================
   LOADING ANIMATION
   ========================================================= */
let msgIdx = 0;

function startLoadingAnimation() {
  scanStage.classList.add('visible');
  scanBtn.classList.add('loading');
  scanBtnText.textContent = 'Scanning…';

  scanLabel.textContent = SCAN_MESSAGES[0];
  msgIdx = 0;

  return setInterval(() => {
    msgIdx = (msgIdx + 1) % SCAN_MESSAGES.length;
    scanLabel.textContent = SCAN_MESSAGES[msgIdx];
  }, 520);
}

/* =========================================================
   UI RESET
   ========================================================= */
function resetUIForScan() {
  resultWrap.classList.remove('visible');
  resultDivider.style.display = 'none';
  resultCard.className = 'result-card';

  mainCard.className = 'card';
  shieldCheck.setAttribute('opacity', '0');
}

/* =========================================================
   RENDER RESULT
   ========================================================= */
function renderResult(url, status, score, detail) {
  scanStage.classList.remove('visible');
  scanBtn.classList.remove('loading');
  scanBtnText.textContent = 'Scan URL';

  resultCard.className = `result-card ${status}`;
  statusIcon.innerHTML = ICONS[status] || ICONS.dangerous;

  statusLabel.textContent =
    status === 'safe' ? 'Safe' :
    status === 'suspicious' ? 'Suspicious' : 'Dangerous';

  riskBadge.textContent = `Risk: ${score}/100`;
  resultUrl.textContent = url.length > 70 ? url.slice(0, 67) + '…' : url;
  scoreValue.textContent = `${score} / 100`;
  resultDetails.textContent = detail;

  resultDivider.style.display = '';
  resultWrap.classList.add('visible');

  scoreBar.style.width = '0%';
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      scoreBar.style.width = score + '%';
    });
  });

  mainCard.classList.add(`glow-${status}`);

  mainCard.addEventListener('animationend', () => {
    mainCard.className = 'card';
  }, { once: true });

  if (status === 'safe') {
    shieldCheck.setAttribute('opacity', '1');
  }
}

/* =========================================================
   SHAKE EFFECT
   ========================================================= */
function shake(el) {
  let start = null;
  const dur = 360;

  function step(ts) {
    if (!start) start = ts;
    const p = (ts - start) / dur;

    if (p >= 1) {
      el.style.transform = 'translateX(0)';
      return;
    }

    el.style.transform =
      `translateX(${Math.sin(p * Math.PI * 6) * 5 * (1 - p)}px)`;

    requestAnimationFrame(step);
  }

  requestAnimationFrame(step);
}

/* =========================================================
   EVENTS
   ========================================================= */
scanBtn.addEventListener('click', startScan);

urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

urlInput.addEventListener('input', () => {
  if (resultWrap.classList.contains('visible')) {
    resultWrap.classList.remove('visible');
    resultDivider.style.display = 'none';
    shieldCheck.setAttribute('opacity', '0');
  }
});