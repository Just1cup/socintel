import requests
import whois
import dns.resolver
import argparse
from datetime import datetime

VT_API_KEY = "SUA_API_VT"
ABUSE_API_KEY = "SUA_API_ABUSE"
OTX_API_KEY = "SUA_API_OTX"

risk = 0
findings = []

# ---------------- IP ----------------
def ip_intel(ip):
    global risk

    # VirusTotal
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(vt_url, headers=headers)
    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        if mal > 0:
            risk += 40
            findings.append(f"VirusTotal: {mal} detecções maliciosas")

    # AbuseIPDB
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(abuse_url, headers=headers, params=params)
    if r.status_code == 200:
        score = r.json()["data"]["abuseConfidenceScore"]
        if score > 0:
            risk += 30
            findings.append(f"AbuseIPDB: score {score}%")

    # AlienVault OTX
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(otx_url, headers=headers)
    if r.status_code == 200:
        pulses = r.json()["pulse_info"]["count"]
        if pulses > 0:
            risk += 25
            findings.append(f"AlienVault OTX: IP presente em {pulses} pulses")

# ---------------- DOMAIN ----------------
def domain_intel(domain):
    global risk

    # VirusTotal
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(vt_url, headers=headers)
    if r.status_code == 200:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        if mal > 0:
            risk += 40
            findings.append(f"VirusTotal: {mal} detecções maliciosas")

    # WHOIS
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.now() - creation).days
        if age < 30:
            risk += 30
            findings.append(f"Domínio criado há {age} dias")
    except:
        findings.append("WHOIS: falha ao obter dados")

    # MX Record
    try:
        dns.resolver.resolve(domain, 'MX')
        findings.append("MX record presente (envio de e-mail possível)")
    except:
        risk += 20
        findings.append("Sem MX record (domínio suspeito)")

    # AlienVault OTX
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(otx_url, headers=headers)
    if r.status_code == 200:
        pulses = r.json()["pulse_info"]["count"]
        if pulses > 0:
            risk += 25
            findings.append(f"AlienVault OTX: domínio presente em {pulses} pulses")

# ---------------- URL ----------------
def url_intel(url):
    global risk

    # URLhaus
    uh_url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {"url": url}
    r = requests.post(uh_url, data=data)
    if r.status_code == 200:
        status = r.json().get("query_status")
        if status == "ok":
            risk += 40
            findings.append("URLhaus: URL listada como maliciosa")

# ---------------- EMAIL ----------------
def email_intel(email):
    if "@" not in email:
        findings.append("Email inválido")
        return
    domain = email.split("@")[1]
    findings.append(f"Domínio do email: {domain}")
    domain_intel(domain)

# ---------------- VERDICT ----------------
def verdict():
    if risk >= 70:
        return "ALTO RISCO – Provável ameaça (escalar / bloquear)"
    elif risk >= 40:
        return "RISCO MÉDIO – Análise adicional recomendada"
    else:
        return "BAIXO RISCO – Possível falso positivo"

# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(description="SOCINTEL v2 - OSINT para SOC N1")
    parser.add_argument("--ip", help="Analisar IP")
    parser.add_argument("--domain", help="Analisar domínio")
    parser.add_argument("--email", help="Analisar email")
    parser.add_argument("--url", help="Analisar URL")

    args = parser.parse_args()

    print("\n🔎 SOCINTEL - RESULTADO\n")

    if args.ip:
        ip_intel(args.ip)
    if args.domain:
        domain_intel(args.domain)
    if args.email:
        email_intel(args.email)
    if args.url:
        url_intel(args.url)

    print(f"RISK SCORE: {risk}/100\n")
    for f in findings:
        print(f"✔ {f}")

    print("\n📌 VEREDITO SOC:")
    print(verdict())

if __name__ == "__main__":
    main()
