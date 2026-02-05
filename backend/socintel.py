"""SOCINTEL backend: multi-source OSINT enrichment with a unified risk score."""
import requests
import dns.resolver
import argparse
import json
import sys
from dotenv import load_dotenv
from pathlib import Path
import os
from datetime import datetime
import socket
import time
import re
dotenv_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=dotenv_path)
from bs4 import BeautifulSoup
from urllib.parse import urlparse

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
URL_IO_KEY = os.getenv("URL_IO_KEY")


risk = 0
findings = []
_sections = set()


def _section(title, desc):
    key = title.lower()
    if key in _sections:
        return
    _sections.add(key)
    findings.append(f"=== {title} — {desc} ===")



def ip_intel(ip):
    global risk

    _section("VirusTotal", "Reputação e detecções de malícia por múltiplos motores")
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(vt_url, headers=headers, timeout=5)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal = stats.get("malicious", 0)
            if mal > 0:
                vt_score = min(mal * 3, 40)
                risk += vt_score
                findings.append(f"VirusTotal: {mal} detecções maliciosas (+{vt_score} pontos)")
            else:
                findings.append(f"VirusTotal: nenhuma detecção maliciosa")
        else:
            findings.append(f"VirusTotal: status {r.status_code}")
    except Exception as e:
        findings.append(f"VirusTotal: erro - {str(e)}")

    _section("AbuseIPDB", "Histórico de abuso reportado para IPs")
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(abuse_url, headers=headers, params=params, timeout=5)
        if r.status_code == 200:
            score = r.json()["data"]["abuseConfidenceScore"]
            if score > 0:
                risk += score
                findings.append(f"AbuseIPDB: score {score}% (+{score} pontos)")
            else:
                findings.append(f"AbuseIPDB: score 0% (sem risco)")
        else:
            findings.append(f"AbuseIPDB: status {r.status_code}")
    except Exception as e:
        findings.append(f"AbuseIPDB: erro - {str(e)}")

    _section("AlienVault OTX", "Threat intel comunitário via pulses")
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(otx_url, headers=headers, timeout=5)
        if r.status_code == 200:
            pulses = r.json()["pulse_info"]["count"]
            if pulses > 0:
                otx_score = min(pulses * 2, 30)
                risk += otx_score
                findings.append(f"AlienVault OTX: IP presente em {pulses} pulses (+{otx_score} pontos)")
            else:
                findings.append(f"AlienVault OTX: IP não encontrado em nenhum pulse")
        else:
            findings.append(f"AlienVault OTX: status {r.status_code}")
    except Exception as e:
        findings.append(f"AlienVault OTX: erro - {str(e)}")

    rdap_ip_intel(ip)


def rdap_ip_intel(ip):
    global risk
    _section("RDAP", "Registro do provedor, país e range do IP")

    rdap_endpoints = [
        f"https://rdap.arin.net/registry/ip/{ip}",
        f"https://rdap.db.ripe.net/ip/{ip}",
        f"https://rdap.apnic.net/ip/{ip}",
        f"https://rdap.lacnic.net/rdap/ip/{ip}",
    ]

    for url in rdap_endpoints:
        try:
            r = requests.get(url, timeout=8)
            if r.status_code != 200:
                continue

            data = r.json()

            name = data.get("name") or data.get("handle") or "unknown"
            country = data.get("country") or "unknown"
            start = data.get("startAddress") or ""
            end = data.get("endAddress") or ""

            findings.append(f"RDAP: owner={name} country={country} range={start}-{end}")
            risk += 2
            return
        except Exception:
            continue
	
    findings.append("RDAP: não foi possível obter dados (endpoints falharam)")

def whois_socket_lookup(domain):
    try:
        whois_server = "whois.iana.org"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((whois_server, 43))
        sock.send(f"{domain}\r\n".encode())
        
        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        sock.close()
        
        resp_text = response.decode('utf-8', errors='ignore')
        
        result = {
            'organization': None,
            'status': None,
            'created': None
        }
        
        lines = resp_text.split('\n')
        for line in lines:
            line_lower = line.lower()
            
            if any(x in line_lower for x in ['organization:', 'org:', 'company:']):
                result['organization'] = line.split(':', 1)[-1].strip()
            
            if 'status:' in line_lower:
                result['status'] = line.split(':', 1)[-1].strip()
            
            if any(x in line_lower for x in ['created:', 'creation date:', 'created date:']):
                result['created'] = line.split(':', 1)[-1].strip()
        
        return result
    except Exception as e:
        return None


def domain_intel(domain):
    global risk

    _section("VirusTotal", "Reputação e detecções de malícia por múltiplos motores")
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(vt_url, headers=headers)
    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        if mal > 0:
            risk += 40
            findings.append(f"VirusTotal: {mal} detecções maliciosas")

    _section("WHOIS", "Registro do domínio e dados cadastrais")
    try:
        whois_data = whois_socket_lookup(domain)
        if whois_data:
            whois_info = [f"WHOIS: Dominio {domain}"]
            if whois_data.get('created'):
                whois_info.append(f"  └─ Registrado em: {whois_data['created']}")
            if whois_data.get('status'):
                whois_info.append(f"  └─ Status: {whois_data['status']}")
            if whois_data.get('organization'):
                whois_info.append(f"  └─ Organização: {whois_data['organization']}")
            else:
                whois_info.append(f"  └─ Organização: Não informada")
            
            findings.extend(whois_info)
        else:
            findings.append("WHOIS: falha ao obter dados")
    except Exception as e:
        findings.append("WHOIS: falha ao obter dados")

    _section("DNS", "Presença de MX e sinais de infraestrutura")
    try:
        dns.resolver.resolve(domain, 'MX')
        findings.append("MX record presente (envio de e-mail possível)")
    except Exception:
        risk += 20
        findings.append("Sem MX record (domínio suspeito)")

    _section("AlienVault OTX", "Threat intel comunitário via pulses")
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(otx_url, headers=headers)
    if r.status_code == 200:
        pulses = r.json()["pulse_info"]["count"]
        if pulses > 0:
            risk += 25
            findings.append(f"AlienVault OTX: domínio presente em {pulses} pulses")
    
    siteconfiavel_intel(domain)

def url_intel(url):
    global risk

    _section("urlscan.io", "Scan e análise de comportamento da URL")
    urlscan_intel(url)

    _section("URLhaus", "Listas de URLs maliciosas conhecidas")
    uh_url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {"url": url}
    r = requests.post(uh_url, data=data)
    if r.status_code == 200:
        status = r.json().get("query_status")
        if status == "ok":
            risk += 40
            findings.append("URLhaus: URL listada como maliciosa")
        else:
            findings.append("URLhaus: URL não encontrada")


def urlscan_intel(url):
    """
    urlscan.io integration following API best practices:
    - API-Key header
    - custom User-Agent
    - search before scan (limited by date)
    - backoff/retry for 429 + transient errors
    - graceful handling of missing fields
    - expose status codes and error messages
    """
    if not URLSCAN_API_KEY:
        findings.append("urlscan.io: API key não configurada (defina URLSCAN_API_KEY)")
        return

    ua = "SOCINTEL/2.0 (urlscan integration)"
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "User-Agent": ua,
        "Accept": "application/json",
    }

    safe_url = _urlscan_escape_query(url)
    query = f'page.url:"{safe_url}" AND date:>now-7d'
    params = {"q": query, "size": 1}

    search = _urlscan_request(
        method="get",
        url="https://urlscan.io/api/v1/search/",
        headers=headers,
        params=params,
    )

    if search["ok"]:
        results = search["json"].get("results", [])
        if results:
            scan_id = results[0].get("_id", "")
            result_url = results[0].get("result", "")
            findings.append("urlscan.io: scan recente encontrado (últimos 7 dias)")
            if scan_id:
                findings.append(f"urlscan.io: scan_id {scan_id}")
            if result_url:
                findings.append(f"urlscan.io: resultado {result_url}")
            _append_urlscan_search_summary(results[0])
            return
        else:
            findings.append("urlscan.io: nenhum scan recente encontrado")
    else:
        findings.append(
            f"urlscan.io: erro na busca (HTTP {search['status']}) {search['error']}"
        )

    visibility = "public"
    if _url_has_pii(url):
        visibility = "unlisted"

    payload = {
        "url": url,
        "visibility": visibility,
        "customagent": ua,
        "tags": ["socintel"],
    }

    submit = _urlscan_request(
        method="post",
        url="https://urlscan.io/api/v1/scan/",
        headers={**headers, "Content-Type": "application/json"},
        json=payload,
    )

    if submit["ok"]:
        scan_id = submit["json"].get("uuid", "")
        result_url = submit["json"].get("result", "")
        findings.append(f"urlscan.io: scan enviado ({visibility})")
        if scan_id:
            findings.append(f"urlscan.io: scan_id {scan_id}")
        if result_url:
            findings.append(f"urlscan.io: resultado {result_url}")

        if scan_id:
            result = _urlscan_result(scan_id, headers)
            if result["ok"]:
                findings.append("urlscan.io: resultado disponível")
                verdicts = result["json"].get("verdicts", {})
                overall = verdicts.get("overall", {})
                overall_score = overall.get("score")
                overall_mal = overall.get("malicious")
                if overall_score is not None:
                    findings.append(f"urlscan.io: score {overall_score}")
                if overall_mal is not None:
                    findings.append(f"urlscan.io: malicious {overall_mal}")
            else:
                findings.append(
                    f"urlscan.io: resultado ainda não disponível (HTTP {result['status']})"
                )

        for attempt in range(2):
            search_after = _urlscan_request(
                method="get",
                url="https://urlscan.io/api/v1/search/",
                headers=headers,
                params=params,
            )
            if search_after["ok"]:
                results_after = search_after["json"].get("results", [])
                if results_after:
                    _append_urlscan_search_summary(results_after[0])
                    break
            time.sleep(1 + attempt)
    else:
        findings.append(
            f"urlscan.io: erro ao enviar scan (HTTP {submit['status']}) {submit['error']}"
        )


def _urlscan_request(method, url, headers, params=None, json=None, max_retries=4):
    """
    Simple exponential backoff with jitter for 429 and transient errors.
    Returns dict with ok, status, json, error.
    """
    backoff = 1.0
    for attempt in range(max_retries + 1):
        try:
            r = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json,
                timeout=12,
                allow_redirects=True,
            )
            status = r.status_code

            if status == 429 or 500 <= status <= 599:
                if attempt == max_retries:
                    return {"ok": False, "status": status, "json": {}, "error": r.text}
                time.sleep(backoff)
                backoff = min(backoff * 2, 16)
                continue

            if status >= 400:
                return {"ok": False, "status": status, "json": {}, "error": r.text}

            try:
                data = r.json()
            except Exception:
                data = {}
            return {"ok": True, "status": status, "json": data, "error": ""}
        except Exception as e:
            if attempt == max_retries:
                return {"ok": False, "status": 0, "json": {}, "error": str(e)}
            time.sleep(backoff)
            backoff = min(backoff * 2, 16)


def _url_has_pii(url):
    return re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", url, re.I) is not None


def _urlscan_escape_query(value):
    return re.sub(r'([+\-=&|><!(){}\[\]^"~*?:\\/])', r"\\\1", value)


def _urlscan_result(scan_id, headers):
    return _urlscan_request(
        method="get",
        url=f"https://urlscan.io/api/v1/result/{scan_id}/",
        headers=headers,
        max_retries=3,
    )


def _append_urlscan_search_summary(result):
    page = result.get("page", {})
    task = result.get("task", {})
    verdicts = result.get("verdicts", {})
    overall = verdicts.get("overall", {})
    engines = verdicts.get("engines", {})
    community = verdicts.get("community", {})
    stats = result.get("stats", {})

    if task.get("time"):
        findings.append(f"urlscan.io: data {task.get('time')}")
    # Avoid linking the scanned URL; use screenshot instead.
    if task.get("screenshotURL"):
        findings.append(f"urlscan.io: screenshot {task.get('screenshotURL')}")
    if task.get("domain"):
        findings.append(f"urlscan.io: domínio {task.get('domain')}")
    if task.get("apexDomain"):
        findings.append(f"urlscan.io: apex {task.get('apexDomain')}")
    if task.get("uuid"):
        findings.append(f"urlscan.io: uuid {task.get('uuid')}")
    if task.get("visibility"):
        findings.append(f"urlscan.io: visibilidade {task.get('visibility')}")
    if task.get("reportURL"):
        findings.append(f"urlscan.io: relatório {task.get('reportURL')}")
    if task.get("screenshotURL"):
        findings.append(f"urlscan.io: screenshot {task.get('screenshotURL')}")
    if task.get("domURL"):
        findings.append(f"urlscan.io: dom {task.get('domURL')}")
    if page.get("ip"):
        findings.append(f"urlscan.io: ip {page.get('ip')}")
    if page.get("country"):
        findings.append(f"urlscan.io: país {page.get('country')}")
    if overall.get("score") is not None:
        findings.append(f"urlscan.io: score {overall.get('score')}")
    if overall.get("malicious") is not None:
        findings.append(f"urlscan.io: malicious {overall.get('malicious')}")
    if engines.get("enginesTotal") is not None:
        findings.append(f"urlscan.io: engines total {engines.get('enginesTotal')}")
    if engines.get("maliciousTotal") is not None:
        findings.append(f"urlscan.io: engines maliciosos {engines.get('maliciousTotal')}")
    if community.get("votesTotal") is not None:
        findings.append(f"urlscan.io: votos comunidade {community.get('votesTotal')}")
    if community.get("votesMalicious") is not None:
        findings.append(f"urlscan.io: votos maliciosos {community.get('votesMalicious')}")
    if stats.get("requests") is not None:
        findings.append(f"urlscan.io: requests {stats.get('requests')}")
    if stats.get("domains") is not None:
        findings.append(f"urlscan.io: domains {stats.get('domains')}")

def hash_intel(hash_value):
    global risk

    _section("VirusTotal", "Reputação e detecções de malícia por múltiplos motores")
    vt_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(vt_url, headers=headers, timeout=5)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal = stats.get("malicious", 0)
            if mal > 0:
                vt_score = min(mal * 3, 40)
                risk += vt_score
                findings.append(f"VirusTotal: {mal} detecções maliciosas (+{vt_score} pontos)")
            else:
                findings.append(f"VirusTotal: hash não detectado como malicioso")
        else:
            findings.append(f"VirusTotal: status {r.status_code}")
    except Exception as e:
        findings.append(f"VirusTotal: erro - {str(e)}")

def email_intel(email):
    if "@" not in email:
        findings.append("Email inválido")
        return
    domain = email.split("@")[1]
    _section("Email", "Extração do domínio para análise")
    findings.append(f"Domínio do email: {domain}")
    domain_intel(domain)

def verdict():
    if risk >= 70:
        return "ALTO RISCO – Provável ameaça (escalar / bloquear)"
    elif risk >= 40:
        return "RISCO MÉDIO – Análise adicional recomendada"
    else:
        return "BAIXO RISCO – Possível falso positivo"

def normalize_mac(mac: str) -> str:
    mac = (mac or "").strip().lower()
    mac = mac.replace("-", ":").replace(".", ":")
    return mac


def mac_intel(mac: str):
    global risk

    _section("MAC Vendors", "Fabricante do dispositivo pelo prefixo MAC")
    mac = normalize_mac(mac)
    if not mac:
        findings.append("MAC Vendor: MAC inválido")
        return

    try:
        r = requests.get(
            f"https://api.macvendors.com/{mac}",
            timeout=8
        )

        if r.status_code == 200 and r.text:
            vendor = r.text.strip()
            findings.append(f"MAC Vendor: {vendor}")
            risk += 1
        elif r.status_code == 404:
            findings.append("MAC Vendor: fabricante não encontrado")
        else:
            findings.append(f"MAC Vendor: erro HTTP {r.status_code}")

    except Exception as e:
        findings.append(f"MAC Vendor: erro - {str(e)}")

def siteconfiavel_intel(target):
    global risk

    _section("SiteConfiavel", "Classificação pública de confiança do site")
    try:
        target = target.strip()

        if target.startswith("http://") or target.startswith("https://"):
            domain = urlparse(target).netloc
        else:
            domain = target

        domain = domain.replace("www.", "")

        url = f"https://www.siteconfiavel.com.br/site/{domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (SOCINTEL OSINT Scanner)"
        }

        r = requests.get(url, headers=headers, timeout=8)

        if r.status_code != 200:
            findings.append("SiteConfiavel: não foi possível consultar")
            return

        soup = BeautifulSoup(r.text, "html.parser")
        page_text = soup.get_text(" ", strip=True).lower()

        if any(x in page_text for x in [
            "não é confiável",
            "nao é confiavel",
            "site perigoso",
            "site suspeito",
            "cuidado"
        ]):
            findings.append("SiteConfiavel: ALERTA – site classificado como NÃO confiável")
            risk += 10

        elif any(x in page_text for x in [
            "site confiável",
            "é confiável",
            "é seguro",
            "site seguro"
        ]):
            findings.append("SiteConfiavel: site classificado como confiável")

        else:
            findings.append("SiteConfiavel: sem classificação clara")

    except Exception as e:
        findings.append(f"SiteConfiavel: erro - {str(e)}")



def print_human():
    print("\n🔎 SOCINTEL - RESULTADO\n")
    capped_risk = min(risk, 100)
    print(f"RISK SCORE: {capped_risk}/100\n")
    for f in findings:
        print(f"✔ {f}")
    print("\n📌 VEREDITO SOC:")
    print(verdict())

def print_json():
    capped_risk = min(risk, 100)
    print(json.dumps({
        "risk": capped_risk,
        "findings": findings,
        "verdict": verdict()
    }))

def main():
    parser = argparse.ArgumentParser(description="SOCINTEL v2 - OSINT para SOC N1")
    parser.add_argument("--ip")
    parser.add_argument("--domain")
    parser.add_argument("--email")
    parser.add_argument("--url")
    parser.add_argument("--hash")
    parser.add_argument("--mac", help="Endereço MAC para identificar fabricante (MACVendors)")
    parser.add_argument("--json", action="store_true", help="Saída em JSON (para GUI)")

    args = parser.parse_args()

    if args.ip:
        ip_intel(args.ip)
    if args.domain:
        domain_intel(args.domain)
    if args.email:
        email_intel(args.email)
    if args.url:
        url_intel(args.url)
    if args.hash:
        hash_intel(args.hash)

    if args.mac:
        mac_intel(args.mac)
    if args.json:
        print_json()
    else:
        print_human()

if __name__ == "__main__":
    main()
