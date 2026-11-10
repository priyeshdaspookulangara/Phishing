/**
 * Real-Time Phishing Website & URL Heuristic Analyzer Frontend Client.
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const scanForm = document.getElementById("scan-form");
  const urlInput = document.getElementById("url-input");
  const clearBtn = document.getElementById("clear-btn");
  const submitBtn = document.getElementById("submit-btn");
  const formError = document.getElementById("form-error");
  const sampleBtns = document.querySelectorAll(".btn-sample");

  const scanningIndicator = document.getElementById("scanning-indicator");
  const resultsPanel = document.getElementById("results-panel");

  const resTargetUrl = document.getElementById("res-target-url");
  const resScanId = document.getElementById("res-scan-id");
  const resTimestamp = document.getElementById("res-timestamp");
  const scoreGaugeCircle = document.getElementById("score-gauge-circle");
  const resScoreNumber = document.getElementById("res-score-number");
  const resRiskBand = document.getElementById("res-risk-band");
  const resFetchStatus = document.getElementById("res-fetch-status");
  const resSignalCount = document.getElementById("res-signal-count");
  const signalsList = document.getElementById("signals-list");
  const resLimitationsList = document.getElementById("res-limitations-list");

  const historyTbody = document.getElementById("history-tbody");
  const historyCount = document.getElementById("history-count");
  const refreshHistoryBtn = document.getElementById("refresh-history-btn");

  // Initial load
  loadHistory();

  // Clear button
  clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    urlInput.focus();
    hideError();
  });

  // Sample Buttons
  sampleBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      urlInput.value = btn.dataset.url;
      hideError();
      urlInput.focus();
    });
  });

  // Refresh history
  refreshHistoryBtn.addEventListener("click", () => {
    loadHistory();
  });

  // Form Submit
  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const targetUrl = urlInput.value.trim();

    if (!targetUrl) {
      showError("Please enter a valid URL to analyze.");
      return;
    }

    hideError();
    setLoadingState(true);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: targetUrl }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `Server returned error status ${response.status}`);
      }

      displayResults(data);
      loadHistory(); // refresh history list
    } catch (err) {
      showError(`Scan execution failed: ${err.message}`);
    } finally {
      setLoadingState(false);
    }
  });

  function showError(msg) {
    formError.textContent = msg;
    formError.style.display = "block";
  }

  function hideError() {
    formError.textContent = "";
    formError.style.display = "none";
  }

  function setLoadingState(isLoading) {
    submitBtn.disabled = isLoading;
    if (isLoading) {
      submitBtn.querySelector(".btn-text").textContent = "ANALYZING...";
      scanningIndicator.style.display = "flex";
      resultsPanel.style.display = "none";
    } else {
      submitBtn.querySelector(".btn-text").textContent = "RUN HEURISTIC SCAN";
      scanningIndicator.style.display = "none";
    }
  }

  function displayResults(data) {
    resultsPanel.style.display = "block";
    resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });

    // Header info
    resTargetUrl.textContent = data.submitted_url;
    resTargetUrl.href = data.submitted_url.startsWith("http") ? data.submitted_url : "http://" + data.submitted_url;
    resScanId.textContent = data.scan_id ? data.scan_id.substring(0, 8) + "..." : "N/A";
    resTimestamp.textContent = data.scanned_at ? new Date(data.scanned_at).toLocaleString() : new Date().toLocaleString();

    // Score & Band
    const score = data.score || 0;
    resScoreNumber.textContent = score;

    scoreGaugeCircle.className = "gauge-circle";
    resRiskBand.className = "risk-band-badge";

    if (score <= 30) {
      scoreGaugeCircle.classList.add("risk-lower");
      resRiskBand.classList.add("band-lower");
      resRiskBand.textContent = data.risk_band || "Lower risk (0-30%)";
    } else if (score <= 70) {
      scoreGaugeCircle.classList.add("risk-suspicious");
      resRiskBand.classList.add("band-suspicious");
      resRiskBand.textContent = data.risk_band || "Suspicious (31-70%)";
    } else {
      scoreGaugeCircle.classList.add("risk-high");
      resRiskBand.classList.add("band-high");
      resRiskBand.textContent = data.risk_band || "High Risk (71-100%)";
    }

    resFetchStatus.textContent = data.fetch_status || "Completed";

    // Signals
    const signals = data.signals || [];
    resSignalCount.textContent = `${signals.length} Signal${signals.length === 1 ? "" : "s"}`;
    signalsList.innerHTML = "";

    if (signals.length === 0) {
      signalsList.innerHTML = `
        <div class="empty-signals">
          <span class="empty-signals-icon">🛡️</span>
          <p>No heuristic risk indicators triggered for this URL.</p>
        </div>
      `;
    } else {
      signals.forEach((sig) => {
        const item = document.createElement("div");
        item.className = "signal-item";

        let sourceClass = "source-url";
        const src = (sig.source || "").toLowerCase();
        if (src.includes("dom") || src.includes("transport")) {
          sourceClass = "source-dom";
          item.classList.add("source-dom");
        } else if (src.includes("safety") || src.includes("ssrf")) {
          sourceClass = "source-safety";
          item.classList.add("source-safety");
        }

        item.innerHTML = `
          <div class="signal-top">
            <div class="signal-meta-left">
              <span class="source-tag ${sourceClass}">${escapeHtml(sig.source || "URL")}</span>
              <span class="signal-name">${escapeHtml(sig.name || sig.id)}</span>
            </div>
            <span class="signal-points">+${sig.points || 0} pts</span>
          </div>
          <div class="signal-desc">${escapeHtml(sig.description || "")}</div>
        `;
        signalsList.appendChild(item);
      });
    }

    // Limitations
    resLimitationsList.innerHTML = "";
    const limitations = data.limitations || [];
    limitations.forEach((lim) => {
      const li = document.createElement("li");
      li.textContent = lim;
      resLimitationsList.appendChild(li);
    });
  }

  async function loadHistory() {
    try {
      const res = await fetch("/api/history?limit=30");
      if (!res.ok) return;
      const data = await res.json();
      renderHistory(data.scans || []);
    } catch (e) {
      console.warn("Could not load scan history:", e);
    }
  }

  function renderHistory(scans) {
    historyCount.textContent = `${scans.length} record${scans.length === 1 ? "" : "s"}`;
    historyTbody.innerHTML = "";

    if (scans.length === 0) {
      historyTbody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-state">No past scans recorded yet. Enter a URL above to perform a scan.</td>
        </tr>
      `;
      return;
    }

    scans.forEach((scan) => {
      const tr = document.createElement("tr");

      let pillClass = "pill-lower";
      if (scan.score > 70) pillClass = "pill-high";
      else if (scan.score > 30) pillClass = "pill-suspicious";

      const timeStr = scan.scanned_at ? new Date(scan.scanned_at).toLocaleString() : "Unknown";

      tr.innerHTML = `
        <td><small style="font-family: var(--font-mono); color: var(--text-muted);">${escapeHtml(timeStr)}</small></td>
        <td><span class="history-url" title="${escapeHtml(scan.submitted_url)}">${escapeHtml(scan.submitted_url)}</span></td>
        <td><strong>${scan.score}/100</strong></td>
        <td><span class="badge-pill ${pillClass}">${escapeHtml(scan.risk_band || "N/A")}</span></td>
        <td><small>${scan.signal_count || (scan.signals ? scan.signals.length : 0)} flags</small></td>
        <td><small style="color: var(--text-muted);">${escapeHtml(truncate(scan.fetch_status, 28))}</small></td>
        <td>
          <button class="btn-table-action view-btn">View Details</button>
        </td>
      `;

      tr.querySelector(".view-btn").addEventListener("click", () => {
        displayResults(scan);
      });

      historyTbody.appendChild(tr);
    });
  }

  function truncate(str, maxLen) {
    if (!str) return "";
    return str.length > maxLen ? str.substring(0, maxLen) + "…" : str;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
