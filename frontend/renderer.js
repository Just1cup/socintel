// UI controller: run analyses, render results, and keep a short history.
function setType(type) {
  document.getElementById("type").value = type;
  const input = document.getElementById("value");
  const placeholders = {
    ip: "Ex: 8.8.8.8",
    domain: "Ex: example.com",
    email: "Ex: user@example.com",
    url: "Ex: https://example.com/login",
    hash: "Ex: d41d8cd98f00b204e9800998ecf8427e",
    mac: "Ex: 00:1A:2B:3C:4D:5E"
  };
  input.placeholder = placeholders[type] || "Digite o indicador";
  
  document.querySelectorAll(".type-btn").forEach(btn => {
    if (btn.dataset.type === type) {
      btn.style.backgroundColor = "var(--color-primary)";
      btn.style.color = "white";
    } else {
      btn.style.backgroundColor = "var(--color-border)";
      btn.style.color = "var(--color-text)";
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

  output.innerText = "Executando análise...\n";
  linksDiv.innerHTML = "";
  badge.innerText = "Analisando...";
  badge.className = "px-3 py-1 rounded text-xs font-bold bg-borderDark text-gray-400";

  try {
    const result = await window.socintel.analyze(type, value);

    let text = `RISK SCORE: ${result.risk}/100\n\n`;
    output.innerHTML = renderFindings(text, result);

    if (result.risk >= 70) {
      badge.innerText = "ALTO RISCO";
      badge.classList.add("bg-danger", "text-white");
    } else if (result.risk >= 40) {
      badge.innerText = "RISCO MÉDIO";
      badge.classList.add("bg-warning", "text-black");
    } else {
      badge.innerText = "BAIXO RISCO";
      badge.classList.add("bg-success", "text-black");
    }

    linksDiv.innerHTML = generateLinks(type, value);

    saveToHistory(type, value);

  } catch (err) {
    output.innerText = "Erro:\n" + err;
    badge.innerText = "ERRO";
    badge.classList.add("bg-danger", "text-white");
  }
}

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

function renderFindings(headerText, result) {
  const lines = [];
  lines.push(linkifyText(headerText));

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
  const output = document.getElementById("output");
  if (!output) return;

  output.addEventListener("mousemove", (e) => {
    const target = e.target;
    if (target && target.classList && target.classList.contains("soc-tooltip-target")) {
      showTooltip(target.dataset.tooltip || "", e.clientX, e.clientY);
    }
  });

  output.addEventListener("mouseleave", () => {
    hideTooltip();
  });
}

// OSINT quick links tailored to indicator type.
function generateLinks(type, value) {
  const links = [];
  const vtUrlId = (url) => {
    const utf8 = new TextEncoder().encode(url);
    let binary = "";
    utf8.forEach((b) => (binary += String.fromCharCode(b)));
    const b64 = btoa(binary);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  if (type === "ip") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/ip-address/${value}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/ip/${value}`, "AlienVault OTX"),
      vtLink(`https://www.abuseipdb.com/check/${value}`, "AbuseIPDB"),
      vtLink(`https://urlscan.io/search/#${encodeURIComponent(value)}`, "urlscan.io")
    );
  }

  if (type === "domain") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/domain/${value}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/domain/${value}`, "AlienVault OTX"),
      vtLink(`https://urlscan.io/search/#${encodeURIComponent(value)}`, "urlscan.io")
    );
  }

  if (type === "url") {
    const vtId = vtUrlId(value);
    links.push(
      vtLink(`https://www.virustotal.com/gui/url/${vtId}`, "VirusTotal"),
      vtLink(`https://urlscan.io/search/#${encodeURIComponent(value)}`, "urlscan.io")
    );
  }

  if (type === "email") {
    const domain = value.split("@")[1];
    links.push(
      vtLink(`https://www.virustotal.com/gui/domain/${domain}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/domain/${domain}`, "AlienVault OTX")
    );
  }

  if (type === "hash") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/file/${value}`, "VirusTotal")
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
