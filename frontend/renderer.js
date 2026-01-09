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

    // Texto principal
    let text = `RISK SCORE: ${result.risk}/100\n\n`;
    result.findings.forEach(f => text += `✔ ${f}\n`);
    text += `\nVEREDITO:\n${result.verdict}`;
    output.innerText = text;

    // Badge de risco
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

    // Links OSINT
    linksDiv.innerHTML = generateLinks(type, value);

  } catch (err) {
    output.innerText = "Erro:\n" + err;
    badge.innerText = "ERRO";
    badge.classList.add("bg-danger", "text-white");
  }
}


function generateLinks(type, value) {
  const links = [];

  if (type === "ip") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/ip-address/${value}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/ip/${value}`, "AlienVault OTX"),
      vtLink(`https://www.abuseipdb.com/check/${value}`, "AbuseIPDB"),
      vtLink(`https://any.run/report/?search=${value}`, "Any.run")
    );
  }

  if (type === "domain") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/domain/${value}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/domain/${value}`, "AlienVault OTX"),
      vtLink(`https://any.run/report/?search=${value}`, "Any.run")
    );
  }

  if (type === "url") {
    links.push(
      vtLink(`https://www.virustotal.com/gui/url/${encodeURIComponent(value)}`, "VirusTotal"),
      vtLink(`https://urlhaus.abuse.ch/url/${encodeURIComponent(value)}/`, "URLhaus"),
      vtLink(`https://any.run/report/?search=${encodeURIComponent(value)}`, "Any.run")
    );
  }

  if (type === "email") {
    const domain = value.split("@")[1];
    links.push(
      vtLink(`https://www.virustotal.com/gui/domain/${domain}`, "VirusTotal"),
      vtLink(`https://otx.alienvault.com/indicator/domain/${domain}`, "AlienVault OTX")
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
