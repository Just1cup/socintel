const { contextBridge } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const script = path.join(__dirname, "../backend/socintel.py");
const logDir = path.join(__dirname, "../backend/logs");

const SAFE_TYPE = new Set(["ip", "web", "email", "hash", "mac"]);

function sanitizeModuleName(value) {
  return String(value || "unknown").replace(/[^a-zA-Z0-9._-]+/g, "_");
}

function writeErrorLog(moduleName, message, details = "") {
  try {
    const now = new Date();
    const ts = now.toISOString().replace("T", "_").split(".")[0].replace(/:/g, "-");
    const safeModule = sanitizeModuleName(moduleName);
    fs.mkdirSync(logDir, { recursive: true });
    const filePath = path.join(logDir, `${ts}_${safeModule}.log`);
    const content = [
      `timestamp: ${ts}`,
      `module: ${moduleName}`,
      `message: ${message}`,
      details ? `details:\n${details}` : ""
    ].filter(Boolean).join("\n") + "\n";
    fs.writeFileSync(filePath, content, "utf8");
  } catch {
    // no-op: logging must never break the flow
  }
}

function detectModuleFromText(text) {
  const t = String(text || "").toLowerCase();
  if (t.includes("urlscan")) return "urlscan.io";
  if (t.includes("virustotal")) return "VirusTotal";
  if (t.includes("abuseipdb")) return "AbuseIPDB";
  if (t.includes("alienvault") || t.includes("otx")) return "AlienVault OTX";
  if (t.includes("whois")) return "WHOIS";
  if (t.includes("rdap")) return "RDAP";
  if (t.includes("dns")) return "DNS";
  if (t.includes("mac")) return "MAC Vendor";
  if (t.includes("siteconfiavel")) return "SiteConfiavel";
  return "backend";
}

function blockDangerousChars(value) {
  return /[\0\r\n`$&|;<>]/.test(value);
}

function isValidIp(value) {
  const isValidIpv4 = (v) => {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return false;
    return v.split(".").every((o) => {
      if (o.length > 1 && o.startsWith("0")) return false;
      const n = Number(o);
      return n >= 0 && n <= 255;
    });
  };

  const isValidHextet = (h) => /^[0-9a-f]{1,4}$/i.test(h);

  const isValidIpv6 = (v) => {
    const parts = v.split("::");
    if (parts.length > 2) return false;

    const left = parts[0] ? parts[0].split(":") : [];
    const right = parts[1] ? parts[1].split(":") : [];

    if (parts.length === 1 && v.includes("::") === false) {
      if (v.startsWith(":") || v.endsWith(":")) return false;
    }

    const all = [...left, ...right];
    let hextetCount = 0;
    for (let i = 0; i < all.length; i += 1) {
      const seg = all[i];
      if (!seg) return false;
      if (seg.includes(".")) {
        if (i !== all.length - 1) return false;
        if (!isValidIpv4(seg)) return false;
        hextetCount += 2;
      } else {
        if (!isValidHextet(seg)) return false;
        hextetCount += 1;
      }
    }

    if (parts.length === 1) {
      return hextetCount === 8;
    }    return hextetCount < 8;
  };

  if (value.includes(":")) return isValidIpv6(value);
  return isValidIpv4(value);
}

function isValidDomain(value) {
  if (value.length > 253) return false;
  if (value.startsWith(".") || value.endsWith(".")) return false;
  const labels = value.split(".");
  if (labels.length < 2) return false;
  return labels.every((l) => /^[a-z0-9-]{1,63}$/i.test(l) && !l.startsWith("-") && !l.endsWith("-"));
}

function isValidUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && !!url.hostname;
  } catch {
    return false;
  }
}

function isValidEmail(value) {
  // Basic sanity check: no spaces, one @, and at least one dot in domain
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) return false;
  const domain = value.split("@")[1];
  return isValidDomain(domain);
}

function isValidHash(value) {
  return /^[a-f0-9]{32}$/i.test(value) || /^[a-f0-9]{40}$/i.test(value) || /^[a-f0-9]{64}$/i.test(value);
}

function normalizeMac(value) {
  return value.replace(/-/g, ":").replace(/\./g, ":").toLowerCase();
}

function isValidMac(value) {
  const v = normalizeMac(value);
  return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(v);
}

function validateInput(type, value) {
  const trimmed = (value || "").trim();
  if (!SAFE_TYPE.has(type)) return { ok: false, reason: "Tipo de IOC inválido." };
  if (!trimmed) return { ok: false, reason: "Valor do IOC vazio." };
  if (blockDangerousChars(trimmed)) {
    return { ok: false, reason: "Valor contém caracteres não permitidos." };
  }

  if (type === "ip" && !isValidIp(trimmed)) return { ok: false, reason: "IP inválido." };
  if (type === "email" && !isValidEmail(trimmed)) return { ok: false, reason: "Email inválido." };
  if (type === "hash" && !isValidHash(trimmed)) return { ok: false, reason: "Hash inválido (MD5/SHA1/SHA256)." };
  if (type === "mac" && !isValidMac(trimmed)) return { ok: false, reason: "MAC inválido." };
  if (type === "web") {
    if (!(isValidDomain(trimmed) || isValidUrl(trimmed))) {
      return { ok: false, reason: "Domínio/URL inválido." };
    }
  }

  return { ok: true, value: type === "mac" ? normalizeMac(trimmed) : trimmed };
}

contextBridge.exposeInMainWorld("socintel", {
  analyze: (type, value) => {
    return new Promise((resolve, reject) => {
      const validation = validateInput(type, value);
      if (!validation.ok) {
        reject(validation.reason);
        return;
      }

      const args = [script, `--${type}`, validation.value, "--json"];
      const child = spawn("python", args, { windowsHide: true });

      let stdout = "";
      let stderr = "";

      child.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      child.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      child.on("error", (err) => {
        writeErrorLog("backend", "Falha ao iniciar o processo Python", err.message);
        reject(err.message);
      });

      child.on("close", (code) => {
        if (code !== 0) {
          try {
            resolve(JSON.parse(stdout));
            return;
          } catch (e) {
            const moduleName = detectModuleFromText(stderr || stdout);
            writeErrorLog(moduleName, `Processo Python saiu com código ${code}`, stderr || stdout);
            reject(stderr || `Processo Python saiu com código ${code}`);
            return;
          }
        }
        try {
          resolve(JSON.parse(stdout));
        } catch (e) {
          const moduleName = detectModuleFromText(stdout);
          writeErrorLog(moduleName, "Saída inválida do Python", stdout);
          reject("Saída inválida do Python:\n" + stdout);
        }
      });
    });
  }
});
