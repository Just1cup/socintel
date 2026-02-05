// UI controller: run analyses, render results, and keep a short history.
function setType(type) {
  document.getElementById("type").value = type;
  
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
    result.findings.forEach(f => text += `✔ ${f}\n`);
    text += `\nVEREDITO:\n${result.verdict}`;
    output.innerHTML = linkifyText(text);

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
  const withLinks = escaped.replace(
    /(https?:\/\/[^\s<>"']+)/g,
    '<a href="$1" target="_blank" rel="noopener noreferrer" class="text-primary underline">$1</a>'
  );
  return withLinks.replace(/\n/g, "<br>");
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// OSINT quick links tailored to indicator type.
function generateLinks(type, value) {
  const links = [];

  if (type === "ip") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/ip-address/${value}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/ip/${value}`, "AlienVault OTX"),
      vtLink(`https://www.abuseipdb.com/check/${value}`, "AbuseIPDB"),
      vtLink(`https://any.run/report/?search=${value}`, "Any.run"),
      vtLink(`https://urlscan.io/search/#${encodeURIComponent(value)}`, "urlscan.io")
    );
  }

  if (type === "domain") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/domain/${value}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/domain/${value}`, "AlienVault OTX"),
      vtLink(`https://any.run/report/?search=${value}`, "Any.run"),
      vtLink(`https://urlscan.io/search/#${encodeURIComponent(value)}`, "urlscan.io")
    );
  }

  if (type === "url") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/url/${encodeURIComponent(value)}`, "VirusTotal"),
      vtLink(`https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(value)}`, "URLhaus"),
      vtLink(`https://any.run/report/?search=${encodeURIComponent(value)}`, "Any.run"),
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
      vtLink(`https://www.virustotal.com/gui/file/${value}`, "VirusTotal"),
      vtLink(`https://bazaar.abuse.ch/browse/?q=${value}`, "Malware Bazaar")
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
