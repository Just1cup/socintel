// UI controller: run analyses, render results, and keep a short history.
function setType(type) {
  if (type === "domain" || type === "url") {
    type = "web";
  }
  document.getElementById("type").value = type;
  const input = document.getElementById("value");
  const placeholders = {
    ip: "Ex: 8.8.8.8",
    web: "Ex: example.com ou https://example.com/login",
    email: "Ex: user@example.com",
    hash: "Ex: d41d8cd98f00b204e9800998ecf8427e",
    mac: "Ex: 00:1A:2B:3C:4D:5E"
  };
  input.placeholder = placeholders[type] || "Digite o indicador";
  
  document.querySelectorAll(".type-btn").forEach(btn => {
    if (btn.dataset.type === type) {
      btn.style.backgroundColor = "var(--color-primary)";
      btn.style.color = "white";
      btn.classList.add("is-active");
    } else {
      btn.style.backgroundColor = "var(--color-border)";
      btn.style.color = "var(--color-text)";
      btn.classList.remove("is-active");
    }
  });
}

const MAX_HISTORY = 10;
let searchHistory = [];

function saveToHistory(type, value) {
  searchHistory.unshift({ type, value, timestamp: new Date().toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }) });
  
  searchHistory = searchHistory.filter((item, index, self) => 
    index === self.findIndex(t => t.type === item.type && t.value === item.value)
  );
  
  searchHistory = searchHistory.slice(0, MAX_HISTORY);
  
  loadHistory();
}

function loadHistory() {
  const historyDiv = document.getElementById("history");
  
  if (searchHistory.length === 0) {
    historyDiv.innerHTML = '<p class="opacity-50">Nenhuma busca recente</p>';
    return;
  }
  
  historyDiv.innerHTML = searchHistory.map((item, index) => `
    <div onclick="loadFromHistory('${item.type}', '${item.value.replace(/'/g, "\\'")}')"
      class="p-2 rounded cursor-pointer transition-colors"
      style="
        background-color: var(--color-bg);
        border: 1px solid var(--color-border);
        color: var(--color-text);
      "
      onmouseover="this.style.backgroundColor='var(--color-border)'"
      onmouseout="this.style.backgroundColor='var(--color-bg)'">
      <div class="font-semibold text-xs">${item.type.toUpperCase()}</div>
      <div class="text-xs opacity-75 truncate">${item.value}</div>
      <div class="text-xs opacity-50">${item.timestamp}</div>
    </div>
  `).join("");
}

function loadFromHistory(type, value) {
  setType(type);
  document.getElementById("value").value = value;
}

document.addEventListener("DOMContentLoaded", loadHistory);
document.addEventListener("DOMContentLoaded", () => setType("ip"));
document.addEventListener("DOMContentLoaded", bindTooltipEvents);

async function analyze() {
  const type = document.getElementById("type").value;
  const value = document.getElementById("value").value;
  const output = document.getElementById("output");
  const badge = document.getElementById("scoreBadge");
  const linksDiv = document.getElementById("links");
  const scanStatus = document.getElementById("scanStatus");
  const scanCountdown = document.getElementById("scanCountdown");
  let countdownTimer = null;

  output.innerText = "Executando análise...\n";
  linksDiv.innerHTML = "";
  badge.innerText = "Analisando...";
  badge.className = "px-3 py-1 rounded text-xs font-bold";
  if (scanStatus) {
    if (shouldShowScanStatus(type, value)) {
      scanStatus.style.display = "flex";
      if (scanCountdown) {
        let remaining = 20;
        scanCountdown.textContent = String(remaining);
        countdownTimer = setInterval(() => {
          remaining -= 1;
          if (remaining <= 0) {
            scanCountdown.textContent = "0";
            clearInterval(countdownTimer);
            countdownTimer = null;
            return;
          }
          scanCountdown.textContent = String(remaining);
        }, 1000);
      }
    } else {
      scanStatus.style.display = "none";
    }
  }

  try {
    const result = await window.socintel.analyze(type, value);

    const headerHtml = renderRiskHeader(result);
    output.innerHTML = renderFindings(headerHtml, result);

    badge.classList.remove("pulse", "badge-high", "badge-med", "badge-low");
    if (result.risk >= 70) {
      badge.innerText = "ALTO RISCO";
      badge.classList.add("badge-high");
    } else if (result.risk >= 40) {
      badge.innerText = "RISCO MÉDIO";
      badge.classList.add("badge-med");
    } else {
      badge.innerText = "BAIXO RISCO";
      badge.classList.add("badge-low");
    }

    linksDiv.innerHTML = generateLinks(type, value, result);
    requestAnimationFrame(() => badge.classList.add("pulse"));

    const tooltipText = buildRiskTooltip(result);
    badge.classList.add("soc-tooltip-target");
    badge.dataset.tooltip = tooltipText;

    if (scanStatus) {
      scanStatus.style.display = "none";
    }
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }

    const urlscanTimeout = result.risk_meta && result.risk_meta.urlscan_timeout;
    if (urlscanTimeout) {
      showErrorModal("Scan da URL não foi concluído a tempo. Aguarde alguns momentos e tente novamente.");
    }

    saveToHistory(type, value);

  } catch (err) {
    const message = humanizeErrorMessage(err);
    showErrorModal(message);
    output.innerText = "";
    linksDiv.innerHTML = "";
    badge.innerText = "ERRO";
    badge.classList.add("badge-high");
    if (scanStatus) {
      scanStatus.style.display = "none";
    }
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
  }
}

function humanizeErrorMessage(err) {
  let message = "";
  if (err && typeof err === "object" && "message" in err) {
    message = String(err.message);
  } else {
    message = String(err);
  }

  const lower = message.toLowerCase();

  if (lower.includes("virustotal")) return "Problema com a API VirusTotal.";
  if (lower.includes("abuseipdb")) return "Problema com a API AbuseIPDB.";
  if (lower.includes("alienvault") || lower.includes("otx")) {
    return "Problema com a API AlienVault OTX.";
  }
  if (lower.includes("scan não foi concluido")) {
    return "Scan da URL não foi concluído com sucesso (limite de 20s).";
  }
  if (lower.includes("urlscan")) return "Problema com a API urlscan.io.";
  if (lower.includes("macvendor")) return "Problema com a API MAC Vendors.";
  if (lower.includes("siteconfiavel") || lower.includes("siteconfiavel.com.br")) {
    return "Problema com o scraping da página SiteConfiavel.";
  }
  if (lower.includes("rdap")) return "Problema com a consulta RDAP.";
  if (lower.includes("whois")) return "Problema com a consulta WHOIS.";
  if (lower.includes("dns")) return "Problema com a consulta DNS.";

  if (lower.includes("inválido") || lower.includes("invalido") || lower.includes("vazio")) {
    return "Problema no indicador informado.";
  }

  return "Ocorreu um problema na análise. Tente novamente.";
}

function showErrorModal(message) {
  const modal = document.getElementById("errorModal");
  const messageEl = document.getElementById("errorModalMessage");
  if (!modal || !messageEl) {
    window.alert(`erro: ${message}`);
    return;
  }

  messageEl.textContent = message;
  modal.classList.add("is-open");
  modal.setAttribute("aria-hidden", "false");
}

function hideErrorModal() {
  const modal = document.getElementById("errorModal");
  if (!modal) return;
  modal.classList.remove("is-open");
  modal.setAttribute("aria-hidden", "true");
}

document.addEventListener("DOMContentLoaded", () => {
  const modal = document.getElementById("errorModal");
  if (!modal) return;

  modal.addEventListener("click", (event) => {
    const target = event.target;
    if (target && target.getAttribute("data-modal-close") === "true") {
      hideErrorModal();
    }
  });
});

function linkifyText(text) {
  const escaped = escapeHtml(text);
  return linkifyEscaped(escaped);
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function linkifyEscaped(escapedText) {
  const withLinks = escapedText.replace(
    /(https?:\/\/[^\s<>"']+)/g,
    '<a href="$1" target="_blank" rel="noopener noreferrer" class="text-primary underline">$1</a>'
  );
  return withLinks.replace(/\n/g, "<br>");
}

function shouldShowScanStatus(type, value) {
  if (type !== "web") return false;
  const trimmed = (value || "").trim();
  return trimmed.length > 0;
}

function buildRiskTooltip(result) {
  const meta = result.risk_meta || {};
  const factors = Array.isArray(result.risk_factors) ? result.risk_factors : [];
  const lines = [];

  lines.push(`Score: ${result.risk}/100 (${meta.level || "N/A"})`);

  if (factors.length) {
    lines.push("Fatores:");
    factors.forEach((f) => {
      const points = typeof f.points === "number" ? f.points : 0;
      const sign = points >= 0 ? "+" : "";
      const source = f.source ? `${f.source}: ` : "";
      const reason = f.reason || "fator não especificado";
      lines.push(`- ${sign}${points} ${source}${reason}`);
    });
  } else {
    lines.push("Fatores: nenhum fator de risco positivo identificado.");
  }

  if (meta.notes && meta.notes.length) {
    lines.push("Ajustes:");
    meta.notes.forEach((note) => lines.push(`- ${note}`));
  }

  return lines.join("\n");
}

function renderRiskHeader(result) {
  const tooltip = escapeHtml(buildRiskTooltip(result));
  const scoreText = escapeHtml(`${result.risk}/100`);
  return (
    `RISK SCORE: ` +
    `<span class="soc-tooltip-target" data-tooltip="${tooltip}" ` +
    `style="text-decoration: underline dotted; cursor: help;">${scoreText}</span>` +
    `\n\n`
  );
}

function renderFindings(headerText, result) {
  const lines = [];
  lines.push(headerText);

  const sectionRegex = /^===\s(.+?)\s—\s(.+?)\s===$/;
  const sourceInfo = {
    "VirusTotal": "Reputação e detecções de malícia por múltiplos motores",
    "AbuseIPDB": "Histórico de abuso reportado para IPs",
    "AlienVault OTX": "Threat intel comunitário via pulses",
    "RDAP": "Registro do provedor, país e range do IP",
    "WHOIS": "Registro do domínio e dados cadastrais",
    "DNS": "Presença de MX e sinais de infraestrutura",
    "urlscan.io": "Scan e análise de comportamento da URL",
    "MAC Vendor": "Fabricante do dispositivo pelo prefixo MAC",
    "SiteConfiavel": "Classificação pública de confiança do site"
  };
  result.findings.forEach(f => {
    const match = f.match(sectionRegex);
    if (match) {
      // Não renderizar linhas de seção; apenas manter descrição para tooltip nas linhas de resultado.
      return;
    }
    const sourceMatch = f.match(/^([A-Za-z0-9 .-]+?):\s/);
    if (sourceMatch) {
      const name = sourceMatch[1];
      const desc = sourceInfo[name];
      if (desc) {
        const safeDesc = escapeHtml(desc);
        const rest = f.slice(name.length + 1).trimStart();
        lines.push(
          `✔ <span class="soc-tooltip-target" data-tooltip="${safeDesc}" style="text-decoration: underline dotted; cursor: help;">${escapeHtml(name)}</span>: ` +
          linkifyEscaped(escapeHtml(rest))
        );
        return;
      }
    }
    lines.push(`✔ ${linkifyText(f)}`);
  });

  lines.push("");
  lines.push(linkifyText(`VEREDITO:\n${result.verdict}`));

  if (result.recommendations && result.recommendations.length > 0) {
    lines.push("");
    lines.push("RECOMENDAÇÕES:");
    result.recommendations.forEach(r => lines.push(`- ${escapeHtml(r)}`));
  }

  return lines.join("<br>");
}

// Custom tooltip (follows mouse) for source summaries.
let tooltipEl = null;

function ensureTooltip() {
  if (tooltipEl) return tooltipEl;
  tooltipEl = document.createElement("div");
  tooltipEl.id = "soc-tooltip";
  tooltipEl.style.position = "fixed";
  tooltipEl.style.pointerEvents = "none";
  tooltipEl.style.zIndex = "9999";
  tooltipEl.style.maxWidth = "260px";
  tooltipEl.style.padding = "8px 10px";
  tooltipEl.style.borderRadius = "6px";
  tooltipEl.style.background = "var(--tooltip-bg)";
  tooltipEl.style.border = "1px solid var(--tooltip-border)";
  tooltipEl.style.color = "var(--tooltip-text)";
  tooltipEl.style.fontSize = "12px";
  tooltipEl.style.boxShadow = "0 6px 18px rgba(0,0,0,0.35)";
  tooltipEl.style.display = "none";
  tooltipEl.innerHTML = `<div style="font-weight: 700; margin-bottom: 4px;">Resumo</div><div id="soc-tooltip-body"></div>`;
  document.body.appendChild(tooltipEl);
  const body = tooltipEl.querySelector("#soc-tooltip-body");
  if (body) {
    body.style.whiteSpace = "pre-line";
  }
  return tooltipEl;
}

function showTooltip(text, x, y) {
  const el = ensureTooltip();
  const body = el.querySelector("#soc-tooltip-body");
  body.textContent = text;
  el.style.left = `${x + 12}px`;
  el.style.top = `${y + 12}px`;
  el.style.display = "block";
}

function hideTooltip() {
  if (!tooltipEl) return;
  tooltipEl.style.display = "none";
}

function bindTooltipEvents() {
  document.addEventListener("mousemove", (e) => {
    const target = e.target;
    if (target && target.classList && target.classList.contains("soc-tooltip-target")) {
      showTooltip(target.dataset.tooltip || "", e.clientX, e.clientY);
    }
  });

  document.addEventListener("mouseleave", () => {
    hideTooltip();
  });
}

// OSINT quick links tailored to indicator type.
function generateLinks(type, value, result) {
  const links = [];
  const safeValue = encodeURIComponent(value);
  const urlscanResultUrl =
    result && result.risk_meta && result.risk_meta.urlscan_result_url
      ? result.risk_meta.urlscan_result_url
      : null;
  const vtUrlId = (url) => {
    const utf8 = new TextEncoder().encode(url);
    let binary = "";
    utf8.forEach((b) => (binary += String.fromCharCode(b)));
    const b64 = btoa(binary);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  if (type === "ip") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/ip-address/${safeValue}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/ip/${safeValue}`, "AlienVault OTX"),
      vtLink(`https://www.abuseipdb.com/check/${safeValue}`, "AbuseIPDB"),
      vtLink(`https://urlscan.io/search/#${safeValue}`, "urlscan.io")
    );
  }

  if (type === "web") {
    const isUrl = /^(https?:\/\/)/i.test(value) || value.includes("/") || value.includes("?");
    if (isUrl) {
      const vtId = vtUrlId(value);
      links.push(
        vtLink(`https://www.virustotal.com/gui/url/${vtId}`, "VirusTotal"),
        vtLink(urlscanResultUrl || `https://urlscan.io/search/#${safeValue}`, "urlscan.io")
      );
    } else {
      links.push(
        vtLink(`https://www.virustotal.com/gui/domain/${safeValue}`, "VirusTotal"),
        vtLink(`https://otx.alienvault.com/indicator/domain/${safeValue}`, "AlienVault OTX"),
        vtLink(urlscanResultUrl || `https://urlscan.io/search/#${safeValue}`, "urlscan.io")
      );
    }
  }

  if (type === "email") {
    const domain = value.split("@")[1];
    links.push(
      vtLink(`https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/domain/${encodeURIComponent(domain)}`, "AlienVault OTX")
    );
  }

  if (type === "hash") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/file/${safeValue}`, "VirusTotal")
    );
  }

  return `
    <div class="border-t border-borderDark pt-3">
      <p class="text-xs text-gray-400 mb-2 uppercase">Links OSINT</p>
      ${links.join("")}
    </div>
  `;
}

function vtLink(url, name) {
  return `
    <a href="${url}" target="_blank"
      class="block bg-bg border border-borderDark rounded px-3 py-2 hover:border-primary transition">
      🔗 ${name}
    </a>
  `;
}
