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
// Tabs switching
const tabUrlBtn      = document.getElementById('tabUrlBtn');
const tabMsgBtn      = document.getElementById('tabMsgBtn');
const urlScanView    = document.getElementById('urlScanView');
const msgScanView    = document.getElementById('msgScanView');

// URL Scanner
const urlInput       = document.getElementById('urlInput');
const scanBtn        = document.getElementById('scanBtn');
const scanBtnText    = document.getElementById('scanBtnText');

// Message Scanner
const senderInput       = document.getElementById('senderInput');
const msgInput       = document.getElementById('msgInput');
const scanMsgBtn     = document.getElementById('scanMsgBtn');
const scanMsgBtnText = document.getElementById('scanMsgBtnText');

// Scan Status Animation stage
const scanStage      = document.getElementById('scanStage');
const scanLabel      = document.getElementById('scanLabel');

// Results layout
const resultWrap      = document.getElementById('resultWrap');
const resultDivider   = document.getElementById('resultDivider');
const resultCard      = document.getElementById('resultCard');
const resultLabelMini = document.getElementById('resultLabelMini');

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
   STATE VARIABLES
   ========================================================= */
let currentScanType = 'url'; // 'url' or 'message'

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

const MSG_SCAN_MESSAGES = [
  'Parsing message content…',
  'Checking for suspicious links…',
  'Analyzing tone and urgency…',
  'Running heuristic checks…',
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
  const scanInterval = startLoadingAnimation(SCAN_MESSAGES, scanBtn, scanBtnText);

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
      (data.reasons || []).join(" • "),
      false
    );

  } catch (err) {
    clearInterval(scanInterval);

    renderResult(
      url,
      "dangerous",
      100,
      "Unable to contact backend server or invalid response.",
      false
    );

    console.error(err);
  }
}

async function performMessageScan(message) {
  const scanInterval = startLoadingAnimation(MSG_SCAN_MESSAGES, scanMsgBtn, scanMsgBtnText);

  try {
    const response = await fetch("http://127.0.0.1:5000/analyze-message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender: senderInput.value.trim(), message: msgInput.value.trim() })
    });

    if (!response.ok) throw new Error("Backend error");

    const data = await response.json();

    clearInterval(scanInterval);

    renderResult(
      data.message || message,
      data.status?.toLowerCase() || "dangerous",
      data.score ?? 100,
      (data.reasons || []).join(" • "),
      true
    );

  } catch (err) {
    clearInterval(scanInterval);

    renderResult(
      message,
      "dangerous",
      100,
      "Unable to contact backend server or invalid response.",
      true
    );

    console.error(err);
  }
}

/* =========================================================
   SCAN ACTIONS
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

function startMessageScan() {
  const raw = msgInput.value.trim();

  // ❌ reject empty input
  if (!raw) {
    shake(msgInput);
    return;
  }

  resetUIForScan();
  performMessageScan(raw);
}

/* =========================================================
   LOADING ANIMATION
   ========================================================= */
let msgIdx = 0;

function startLoadingAnimation(messages, btn, btnText) {
  scanStage.classList.add('visible');
  btn.classList.add('loading');
  btnText.textContent = 'Scanning…';

  scanLabel.textContent = messages[0];
  msgIdx = 0;

  return setInterval(() => {
    msgIdx = (msgIdx + 1) % messages.length;
    scanLabel.textContent = messages[msgIdx];
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
function renderResult(content, status, score, detail, isMessage = false) {
  scanStage.classList.remove('visible');
  
  scanBtn.classList.remove('loading');
  scanBtnText.textContent = 'Scan URL';

  scanMsgBtn.classList.remove('loading');
  scanMsgBtnText.textContent = 'Scan Message';

  resultCard.className = `result-card ${status}`;
  statusIcon.innerHTML = ICONS[status] || ICONS.dangerous;

  statusLabel.textContent =
    status === 'safe' ? 'Safe' :
    status === 'suspicious' ? 'Suspicious' : 'Dangerous';

  riskBadge.textContent = `Risk: ${score}/100`;

  if (isMessage) {
    resultUrl.classList.add('message-type');
    resultUrl.textContent = content.length > 500 ? content.slice(0, 497) + '…' : content;
  } else {
    resultUrl.classList.remove('message-type');
    resultUrl.textContent = content.length > 70 ? content.slice(0, 67) + '…' : content;
  }

  resultLabelMini.textContent = isMessage ? 'Scanned Message' : 'Scanned URL';
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
   TAB SWITCHING LOGIC
   ========================================================= */
function switchTab(tabType) {
  currentScanType = tabType;
  
  if (tabType === 'url') {
    tabUrlBtn.classList.add('active');
    tabMsgBtn.classList.remove('active');
    urlScanView.classList.add('active');
    msgScanView.classList.remove('active');
  } else {
    tabMsgBtn.classList.add('active');
    tabUrlBtn.classList.remove('active');
    msgScanView.classList.add('active');
    urlScanView.classList.remove('active');
  }

  resetUIForScan();
}

/* =========================================================
   EVENTS
   ========================================================= */
tabUrlBtn.addEventListener('click', () => switchTab('url'));
tabMsgBtn.addEventListener('click', () => switchTab('message'));

scanBtn.addEventListener('click', startScan);
scanMsgBtn.addEventListener('click', startMessageScan);

urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

msgInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    startMessageScan();
  }
});

urlInput.addEventListener('input', () => {
  if (resultWrap.classList.contains('visible') && currentScanType === 'url') {
    resultWrap.classList.remove('visible');
    resultDivider.style.display = 'none';
    shieldCheck.setAttribute('opacity', '0');
  }
});

msgInput.addEventListener('input', () => {
  if (resultWrap.classList.contains('visible') && currentScanType === 'message') {
    resultWrap.classList.remove('visible');
    resultDivider.style.display = 'none';
    shieldCheck.setAttribute('opacity', '0');
  }
});