const totalCount = document.getElementById("total-count");
const safeCount = document.getElementById("safe-count");
const suspiciousCount = document.getElementById("suspicious-count");
const safePercent = document.getElementById("safe-percent");
const suspiciousPercent = document.getElementById("suspicious-percent");
const safeBar = document.getElementById("safe-bar");
const suspiciousBar = document.getElementById("suspicious-bar");
const packetTableBody = document.getElementById("packet-table-body");
const suspiciousTableBody = document.getElementById("suspicious-table-body");
const statusText = document.getElementById("status-text");
const modeSelect = document.getElementById("mode-select");
const interfaceSelect = document.getElementById("interface-select");
const packetLimitInput = document.getElementById("packet-limit");
const dashboardTitle = document.getElementById("dashboard-title");
const easterEggToast = document.getElementById("easter-egg-toast");
let titleTapCount = 0;
let titleTapTimer = null;

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }
  return payload;
}

function renderSummary(summary) {
  const total = summary.total || 0;
  const safe = summary.safe || 0;
  const suspicious = summary.suspicious || 0;
  const safeRatio = total ? Math.round((safe / total) * 100) : 0;
  const suspiciousRatio = total ? Math.round((suspicious / total) * 100) : 0;

  totalCount.textContent = total;
  safeCount.textContent = safe;
  suspiciousCount.textContent = suspicious;
  safePercent.textContent = `${safeRatio}%`;
  suspiciousPercent.textContent = `${suspiciousRatio}%`;
  safeBar.style.width = `${safeRatio}%`;
  suspiciousBar.style.width = `${suspiciousRatio}%`;
}

function renderPackets(packets) {
  if (!packets.length) {
    packetTableBody.innerHTML = `
      <tr>
        <td colspan="7" class="empty-state">No packets captured yet.</td>
      </tr>
    `;
    return;
  }

  packetTableBody.innerHTML = packets.map((packet) => {
    const reason = packet.reasons.length ? packet.reasons.join("; ") : "Normal traffic";
    const statusClass = packet.status.toLowerCase();
    return `
      <tr>
        <td>${packet.id}</td>
        <td>${packet.source_ip}</td>
        <td>${packet.destination_ip}</td>
        <td>${packet.protocol}</td>
        <td><span class="status-pill ${statusClass}">${packet.status}</span></td>
        <td>${packet.ml_label || "Unavailable"}</td>
        <td>${reason}</td>
      </tr>
    `;
  }).join("");
}

function renderSuspiciousPackets(packets) {
  if (!packets.length) {
    suspiciousTableBody.innerHTML = `
      <tr>
        <td colspan="6" class="empty-state">No suspicious packets captured yet.</td>
      </tr>
    `;
    return;
  }

  suspiciousTableBody.innerHTML = packets.map((packet) => `
    <tr>
      <td>${packet.id}</td>
      <td>${packet.source_ip}</td>
      <td>${packet.protocol}</td>
      <td>${packet.ml_label || "Unavailable"}</td>
      <td>${packet.ml_confidence ?? "-"}</td>
      <td>${packet.reasons.length ? packet.reasons.join("; ") : "Flagged"}</td>
    </tr>
  `).join("");
}

async function refreshDashboard() {
  try {
    const [summary, packets, suspiciousPackets, status] = await Promise.all([
      fetchJson("/api/summary"),
      fetchJson("/api/packets?limit=50"),
      fetchJson("/api/suspicious?limit=50"),
      fetchJson("/api/status"),
    ]);
    renderSummary(summary);
    renderPackets(packets);
    renderSuspiciousPackets(suspiciousPackets);
    const modelText = status.ml_model_ready ? "ML model active" : "ML model unavailable";
    statusText.textContent = status.running ? `Running in ${status.mode} mode • ${modelText}` : `Idle • ${modelText}`;
  } catch (error) {
    statusText.textContent = error.message;
  }
}

async function loadInterfaces() {
  try {
    const payload = await fetchJson("/api/interfaces");
    const interfaces = payload.interfaces || [];
    if (!interfaces.length) {
      interfaceSelect.innerHTML = `<option value="">No interfaces found</option>`;
      return;
    }
    interfaceSelect.innerHTML = interfaces.map((item, index) => `
      <option value="${item.id}" ${index === 0 ? "selected" : ""}>${item.label}</option>
    `).join("");
  } catch (error) {
    interfaceSelect.innerHTML = `<option value="">Unable to load interfaces</option>`;
  }
}

async function startCapture() {
  try {
    const packetLimit = Number(packetLimitInput.value) || 50;
    const selectedInterface = interfaceSelect.value;
    if (!selectedInterface) {
      throw new Error("Select a network interface before starting live capture.");
    }
    const payload = {
      mode: modeSelect.value,
      interface: selectedInterface,
      packet_limit: packetLimit,
    };
    const result = await fetchJson("/api/capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    statusText.textContent = `Capture started in ${result.mode} mode`;
    refreshDashboard();
  } catch (error) {
    statusText.textContent = error.message;
  }
}

async function stopCapture() {
  await fetchJson("/api/capture/stop", { method: "POST" });
  statusText.textContent = "Capture stopped";
  refreshDashboard();
}

async function resetDashboard() {
  await fetchJson("/api/reset", { method: "POST" });
  statusText.textContent = "Data reset";
  refreshDashboard();
}

document.getElementById("start-btn").addEventListener("click", startCapture);
document.getElementById("stop-btn").addEventListener("click", stopCapture);
document.getElementById("reset-btn").addEventListener("click", resetDashboard);

function showEasterEgg() {
  easterEggToast.hidden = false;
  requestAnimationFrame(() => easterEggToast.classList.add("visible"));
  clearTimeout(titleTapTimer);
  titleTapTimer = setTimeout(() => {
    easterEggToast.classList.remove("visible");
    setTimeout(() => {
      easterEggToast.hidden = true;
    }, 250);
  }, 3200);
}

dashboardTitle.addEventListener("click", () => {
  titleTapCount += 1;
  clearTimeout(titleTapTimer);
  titleTapTimer = setTimeout(() => {
    titleTapCount = 0;
  }, 1200);

  if (titleTapCount >= 5) {
    titleTapCount = 0;
    showEasterEgg();
  }
});

loadInterfaces();
refreshDashboard();
setInterval(refreshDashboard, 2000);
