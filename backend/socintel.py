import requests
import whois
import dns.resolver
import argparse
import json
import sys
from dotenv import load_dotenv
import os
from datetime import datetime
load_dotenv()
from bs4 import BeautifulSoup
from urllib.parse import urlparse

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")


risk = 0
findings = []



def ip_intel(ip):
    global risk

    # VirusTotal
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

    # AbuseIPDB
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

    # AlienVault OTX
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

    # RDAP / ASN / Owner enrichment
    rdap_ip_intel(ip)


def rdap_ip_intel(ip):
    """
    Enriquecimento via RDAP (sem API key): owner/handle, país e range.
    NÃO indica malícia por si só, então soma poucos pontos.
    """
    global risk

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

def domain_intel(domain):
    global risk

    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(vt_url, headers=headers)
    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        if mal > 0:
            risk += 40
            findings.append(f"VirusTotal: {mal} detecções maliciosas")

    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = (datetime.now() - creation).days
            if age < 30:
                risk += 30
                findings.append(f"Domínio criado há {age} dias")
    except Exception:
        findings.append("WHOIS: falha ao obter dados")

    try:
        dns.resolver.resolve(domain, 'MX')
        findings.append("MX record presente (envio de e-mail possível)")
    except Exception:
        risk += 20
        findings.append("Sem MX record (domínio suspeito)")

    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(otx_url, headers=headers)
    if r.status_code == 200:
        pulses = r.json()["pulse_info"]["count"]
        if pulses > 0:
            risk += 25
            findings.append(f"AlienVault OTX: domínio presente em {pulses} pulses")

def url_intel(url):
    global risk

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

def hash_intel(hash_value):
    global risk

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
            risk += 1  # enrichment leve
        elif r.status_code == 404:
            findings.append("MAC Vendor: fabricante não encontrado")
        else:
            findings.append(f"MAC Vendor: erro HTTP {r.status_code}")

    except Exception as e:
        findings.append(f"MAC Vendor: erro - {str(e)}")

def siteconfiavel_intel(target):
    global risk

    try:
        # Normaliza domínio
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

        # Heurísticas SOC-friendly
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
