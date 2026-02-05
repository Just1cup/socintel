"""SOCINTEL backend: multi-source OSINT enrichment with a unified risk score."""
import requests
import dns.resolver
import argparse
import json
import sys
import concurrent.futures
import threading
import time
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
_lock = threading.Lock()
positive_hits = 0
active_ioc_type = "generic"
timings = {}


def _add_risk(delta):
    global risk
    with _lock:
        risk += delta


def _add_hit():
    global positive_hits
    with _lock:
        positive_hits += 1


def _timeit(name, fn):
    start = time.perf_counter()
    try:
        return fn()
    finally:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        with _lock:
            timings[name] = elapsed_ms




def _section(title, desc):
    key = title.lower()
    with _lock:
        if key in _sections:
            return
        _sections.add(key)
        findings.append(f"=== {title} — {desc} ===")



def ip_intel(ip):
    def vt_task():
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
                    _add_risk(vt_score)
                    _add_hit()
                    findings.append(f"VirusTotal: {mal} detecções maliciosas (+{vt_score} pontos)")
                else:
                    findings.append("VirusTotal: nenhuma detecção maliciosa")
            else:
                findings.append(f"VirusTotal: status {r.status_code}")
        except Exception as e:
            findings.append(f"VirusTotal: erro - {str(e)}")

    def abuse_task():
        _section("AbuseIPDB", "Histórico de abuso reportado para IPs")
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            r = requests.get(abuse_url, headers=headers, params=params, timeout=5)
            if r.status_code == 200:
                score = r.json()["data"]["abuseConfidenceScore"]
                if score > 0:
                    _add_risk(score)
                    _add_hit()
                    findings.append(f"AbuseIPDB: score {score}% (+{score} pontos)")
                else:
                    findings.append("AbuseIPDB: score 0% (sem risco)")
            else:
                findings.append(f"AbuseIPDB: status {r.status_code}")
        except Exception as e:
            findings.append(f"AbuseIPDB: erro - {str(e)}")

    def otx_task():
        _section("AlienVault OTX", "Threat intel comunitário via pulses")
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        try:
            r = requests.get(otx_url, headers=headers, timeout=5)
            if r.status_code == 200:
                pulses = r.json()["pulse_info"]["count"]
                if pulses > 0:
                    otx_score = min(pulses * 2, 30)
                    _add_risk(otx_score)
                    _add_hit()
                    findings.append(f"AlienVault OTX: IP presente em {pulses} pulses (+{otx_score} pontos)")
                else:
                    findings.append("AlienVault OTX: IP não encontrado em nenhum pulse")
            else:
                findings.append(f"AlienVault OTX: status {r.status_code}")
        except Exception as e:
            findings.append(f"AlienVault OTX: erro - {str(e)}")

    def rdap_task():
        rdap_ip_intel(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(_timeit, "VirusTotal", vt_task),
            executor.submit(_timeit, "AbuseIPDB", abuse_task),
            executor.submit(_timeit, "AlienVault OTX", otx_task),
            executor.submit(_timeit, "RDAP", rdap_task),
        ]
        for f in futures:
            f.result()


def rdap_ip_intel(ip):
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
            _add_risk(2)
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
    def vt_task():
        _section("VirusTotal", "Reputação e detecções de malícia por múltiplos motores")
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            r = requests.get(vt_url, headers=headers, timeout=5)
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                mal = stats.get("malicious", 0)
                if mal > 0:
                    _add_risk(40)
                    _add_hit()
                    findings.append(f"VirusTotal: {mal} detecções maliciosas")
        except Exception as e:
            findings.append(f"VirusTotal: erro - {str(e)}")

    def whois_task():
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
                    whois_info.append("  └─ Organização: Não informada")
                findings.extend(whois_info)
            else:
                findings.append("WHOIS: falha ao obter dados")
        except Exception:
            findings.append("WHOIS: falha ao obter dados")

    def dns_task():
        _section("DNS", "Presença de MX e sinais de infraestrutura")
        try:
            dns.resolver.resolve(domain, 'MX')
            findings.append("MX record presente (envio de e-mail possível)")
        except Exception:
            _add_risk(20)
            _add_hit()
            findings.append("Sem MX record (domínio suspeito)")

    def otx_task():
        _section("AlienVault OTX", "Threat intel comunitário via pulses")
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        try:
            r = requests.get(otx_url, headers=headers, timeout=5)
            if r.status_code == 200:
                pulses = r.json()["pulse_info"]["count"]
                if pulses > 0:
                    _add_risk(25)
                    _add_hit()
                    findings.append(f"AlienVault OTX: domínio presente em {pulses} pulses")
        except Exception as e:
            findings.append(f"AlienVault OTX: erro - {str(e)}")

    def siteconfiavel_task():
        siteconfiavel_intel(domain)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(_timeit, "VirusTotal", vt_task),
            executor.submit(_timeit, "WHOIS", whois_task),
            executor.submit(_timeit, "DNS", dns_task),
            executor.submit(_timeit, "AlienVault OTX", otx_task),
            executor.submit(_timeit, "SiteConfiavel", siteconfiavel_task),
        ]
        for f in futures:
            f.result()

def url_intel(url):
    def urlscan_task():
        _section("urlscan.io", "Scan e análise de comportamento da URL")
        urlscan_intel(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        futures = [
            executor.submit(_timeit, "urlscan.io", urlscan_task),
        ]
        for f in futures:
            f.result()


def web_intel(value):
    _section("Web", "Análise combinada de domínio e URL")
    value = (value or "").strip()
    url_value = None
    domain_value = None

    if value.startswith("http://") or value.startswith("https://"):
        url_value = value
        domain_value = urlparse(value).netloc
    elif "/" in value or "?" in value:
        url_value = "http://" + value
        domain_value = urlparse(url_value).netloc
    else:
        domain_value = value

    if domain_value:
        domain_intel(domain_value)
    if url_value:
        url_intel(url_value)


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
    _section("VirusTotal", "Reputação e detecções de malícia por múltiplos motores")
    vt_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(vt_url, headers=headers, timeout=5)
        if r.status_code == 200:
            attributes = r.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            if mal > 0:
                vt_score = min(mal * 3, 40)
                _add_risk(vt_score)
                _add_hit()
                findings.append(f"VirusTotal: {mal} detecções maliciosas (+{vt_score} pontos)")
            else:
                findings.append(f"VirusTotal: hash não detectado como malicioso")
            file_name = attributes.get("meaningful_name")
            if not file_name:
                names = attributes.get("names") or []
                if names:
                    file_name = names[0]
            if file_name:
                findings.append(f"VirusTotal: nome do executável {file_name}")
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

def _risk_profile(ioc_type):
    max_by_type = {
        "ip": 172,
        "domain": 95,
        "url": 40,
        "hash": 40,
        "email": 95,
        "mac": 10,
        "generic": 100,
    }
    max_score = max_by_type.get(ioc_type, 100)
    normalized = int(min(max(risk / max_score * 100, 0), 100))

    if normalized >= 70 and positive_hits < 2:
        normalized = 69
        findings.append("Validação: apenas uma fonte positiva; risco ajustado para evitar alertas isolados")

    if normalized >= 70:
        level = "ALTO"
    elif normalized >= 40:
        level = "MÉDIO"
    else:
        level = "BAIXO"

    return normalized, level


def _recommendations(ioc_type, level, normalized):
    base = {
        "ALTO": [
            "Sinais fortes de maliciosidade nas bases consultadas",
            "Priorizar a correlação com logs e alertas do cliente",
        ],
        "MÉDIO": [
            "Indícios moderados nas bases consultadas",
            "Reforçar monitoramento e correlacionar com eventos internos",
        ],
        "BAIXO": [
            "Sem sinais relevantes nas bases consultadas",
            "Manter monitoramento e reavaliar se houver novos alertas",
        ],
    }
    by_ioc = {
        "ip": {
            "ALTO": ["IP listado como malicioso em múltiplas fontes; destacar para o cliente"],
            "MÉDIO": ["IP com sinais parciais; correlacionar com tráfego recente"],
            "BAIXO": ["IP não encontrado como malicioso nas bases consultadas; validar geolocalização/ASN"],
        },
        "domain": {
            "ALTO": ["Domínio com reputação negativa; correlacionar com acessos e alertas do cliente"],
            "MÉDIO": ["Domínio com sinais moderados; monitorar DNS/WHOIS e acessos"],
            "BAIXO": ["Domínio não encontrado como malicioso nas bases consultadas; acompanhar DNS/WHOIS"],
        },
        "url": {
            "ALTO": ["URL classificada como maliciosa; correlacionar com acessos do cliente"],
            "MÉDIO": ["URL com indícios; revisar contexto e origem"],
            "BAIXO": ["URL não encontrada como maliciosa nas bases consultadas; reavaliar se houver novos eventos"],
        },
        "hash": {
            "ALTO": ["Hash com detecções confirmadas; correlacionar com endpoints do cliente"],
            "MÉDIO": ["Hash com sinais parciais; verificar prevalência e origem"],
            "BAIXO": ["Hash não encontrado como malicioso nas bases consultadas; monitorar por novas detecções"],
        },
        "email": {
            "ALTO": ["Remetente/domínio com sinais de abuso; correlacionar com alertas de phishing"],
            "MÉDIO": ["Sinais moderados; verificar SPF/DMARC e reputação do domínio"],
            "BAIXO": ["Domínio do email não encontrado como malicioso nas bases consultadas; manter monitoramento"],
        },
        "mac": {
            "ALTO": ["MAC associado a fabricante suspeito; correlacionar com inventário do cliente"],
            "MÉDIO": ["MAC com fabricante incomum; monitorar comportamento na rede"],
            "BAIXO": ["Fabricante identificado; sem sinais de risco nas bases consultadas"],
        },
        "generic": {},
    }
    recs = base[level] + by_ioc.get(ioc_type, {}).get(level, [])
    if normalized > 25 and ioc_type in {"ip", "domain", "url", "email", "hash"}:
        siem_queries = {
            "ip": "QRadar:\n- Como buscar: Add Filter (Source IP, Destination IP ou Source IP OR Destination IP)\n- Por quê: identificar origem/destino do tráfego e se o IP é atacante, vítima ou pivô\n- Group By: Source IP / Destination IP / Username",
            "domain": "QRadar:\n- Como buscar: Events -> botão direito no domínio -> Filter on value, depois Search e usar Group By\n- Por quê: comunicação suspeita (C2, download, exfiltração)\n- Group By: Destination IP / Hostname / Username",
            "url": "QRadar:\n- Como buscar: Add Filter (URL ou HTTP Request URL) ou Payload contains <URL>\n- Por quê: acesso a site malicioso ou download\n- Group By: URL / Source IP / Username",
            "email": "QRadar:\n- Como buscar: Add Filter (Sender, Recipient) ou Payload contains <email>\n- Por quê: phishing ou campanha de e-mail\n- Group By: Sender / Recipient / Subject",
            "hash": "QRadar:\n- Como buscar: Add Filter (Payload contains <hash>) e campos de processo (se houver)\n- Por quê: identificar execução de malware\n- Group By: Hostname / Process Name / Username",
            "mac": "QRadar:\n- Como buscar: Add Filter (MAC Address, Source MAC, Destination MAC)\n- Por quê: identificar dispositivo na rede\n- Group By: MAC / IP / Hostname",
        }
        recs.append(siem_queries.get(ioc_type, "Buscar no SIEM por eventos relacionados ao indicador"))
    return recs


def verdict():
    normalized, level = _risk_profile(active_ioc_type)
    if level == "ALTO":
        return f"ALTO RISCO – provável ameaça. Score {normalized}/100"
    if level == "MÉDIO":
        return f"RISCO MÉDIO – análise adicional recomendada. Score {normalized}/100"
    return f"BAIXO RISCO – sem sinais relevantes nas bases consultadas. Score {normalized}/100"

def normalize_mac(mac: str) -> str:
    mac = (mac or "").strip().lower()
    mac = mac.replace("-", ":").replace(".", ":")
    return mac


def mac_intel(mac: str):
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
            _add_risk(1)
            _add_hit()
        elif r.status_code == 404:
            findings.append("MAC Vendor: fabricante não encontrado")
        else:
            findings.append(f"MAC Vendor: erro HTTP {r.status_code}")

    except Exception as e:
        findings.append(f"MAC Vendor: erro - {str(e)}")

def siteconfiavel_intel(target):
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
            _add_risk(10)
            _add_hit()

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
    normalized, level = _risk_profile(active_ioc_type)
    print(f"RISK SCORE: {normalized}/100 ({level})\n")
    for f in findings:
        print(f"✔ {f}")
    print("\n📌 VEREDITO SOC:")
    print(verdict())
    print("\n✅ RECOMENDAÇÕES:")
    for rec in _recommendations(active_ioc_type, level, normalized):
        print(f"- {rec}")

def print_json():
    normalized, level = _risk_profile(active_ioc_type)
    print(json.dumps({
        "risk": normalized,
        "level": level,
        "findings": findings,
        "verdict": verdict(),
        "recommendations": _recommendations(active_ioc_type, level, normalized),
        "timings_ms": timings
    }))

def main():
    global active_ioc_type
    parser = argparse.ArgumentParser(description="SOCINTEL v2 - OSINT para SOC N1")
    parser.add_argument("--ip")
    parser.add_argument("--domain")
    parser.add_argument("--email")
    parser.add_argument("--url")
    parser.add_argument("--web")
    parser.add_argument("--hash")
    parser.add_argument("--mac", help="Endereço MAC para identificar fabricante (MACVendors)")
    parser.add_argument("--json", action="store_true", help="Saída em JSON (para GUI)")

    args = parser.parse_args()

    if args.ip:
        active_ioc_type = "ip"
        ip_intel(args.ip)
    if args.web:
        active_ioc_type = "web"
        web_intel(args.web)
    if args.domain:
        active_ioc_type = "web"
        web_intel(args.domain)
    if args.email:
        active_ioc_type = "email"
        email_intel(args.email)
    if args.url:
        active_ioc_type = "web"
        web_intel(args.url)
    if args.hash:
        active_ioc_type = "hash"
        hash_intel(args.hash)

    if args.mac:
        active_ioc_type = "mac"
        mac_intel(args.mac)
    if args.json:
        print_json()
    else:
        print_human()

if __name__ == "__main__":
    main()
