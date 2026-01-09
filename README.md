# SOCINTEL

SOCINTEL é uma ferramenta **OSINT / Threat Intelligence** voltada para uso em **SOC (Security Operations Center)**, permitindo análise de **IP, domínio, URL e email** tanto via **linha de comando (CLI)** quanto por uma **interface gráfica (GUI)** construída com **Electron + Tailwind CSS**.

O projeto foi pensado para funcionar em **ambientes Linux (testado em Arch Linux)**, com foco em analistas N1/N2.

---

## 📌 Funcionalidades

* Análise de IP, domínio, URL e email
* Score de risco consolidado (0–100)
* Integração com:

  * VirusTotal
  * AbuseIPDB
  * AlienVault OTX
  * URLhaus
  * Any.run (links externos)
* Saída dupla:

  * **Humana** (CLI)
  * **JSON** (GUI)
* Interface moderna estilo SOC (Any.run / OpenCTI / VirusTotal)

---

## 📂 Estrutura do Projeto

```
socintel/
├── backend/
│   ├── socintel.py
│   └── requirements.txt
│
├── frontend/
│   ├── main.js
│   ├── preload.js
│   ├── renderer.js
│   ├── index.html
│   └── package.json
│
└── README.md
```

---

## 🔧 Dependências

### Backend (Python)

* Python 3.9+
* requests
* python-whois
* dnspython

Instalação:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Exemplo de `requirements.txt`:

```
requests
python-whois
dnspython
```

---

### Frontend (Electron)

* Node.js 18+
* npm
* Electron

Instalação:

```bash
cd frontend
npm install
```

---

## ▶️ Uso via CLI (Terminal)

O modo CLI é ideal para automações, scripts e uso direto por analistas.

### Analisar IP

```bash
python3 socintel.py --ip 8.8.8.8
```

### Analisar domínio

```bash
python3 socintel.py --domain example.com
```

### Analisar URL

```bash
python3 socintel.py --url https://example.com/login
```

### Analisar email

```bash
python3 socintel.py --email user@example.com
```

### Saída em JSON (integração / GUI)

```bash
python3 socintel.py --ip 8.8.8.8 --json
```

Saída:

```json
{
  "risk": 65,
  "findings": ["VirusTotal: 3 detecções maliciosas"],
  "verdict": "RISCO MÉDIO – Análise adicional recomendada"
}
```

---

## 🖥️ Uso via GUI (Electron)

### Executar em modo desenvolvimento

```bash
cd frontend
npm start
```

A interface gráfica permite:

* Selecionar o tipo de análise
* Inserir o valor
* Visualizar score, veredito e evidências
* Acessar links diretos para plataformas OSINT

---

## 🔗 Links OSINT Integrados

Após cada análise, a GUI apresenta links diretos para investigação:

* VirusTotal
* AlienVault OTX
* AbuseIPDB
* URLhaus
* Any.run

Os links são gerados dinamicamente com base no tipo de entidade analisada.

---

## 📦 Compilação da GUI (Build)

Para gerar um executável distribuível da interface gráfica:

### 1️⃣ Instalar electron-builder

```bash
npm install --save-dev electron-builder
```

### 2️⃣ Atualizar `package.json`

```json
{
  "name": "socintel-ui",
  "version": "1.0.0",
  "main": "main.js",
  "scripts": {
    "start": "electron .",
    "build": "electron-builder"
  },
  "build": {
    "appId": "com.socintel.app",
    "linux": {
      "target": ["AppImage"],
      "category": "Security"
    }
  }
}
```

### 3️⃣ Gerar build

```bash
npm run build
```

O executável será gerado em:

```
frontend/dist/
```

---

## ⚠️ Observações Importantes

* As chaves de API devem ser configuradas diretamente no backend (.env)
* Recomenda-se uso de **virtualenv** no backend
* A GUI depende do Python estar acessível via `python3`
* Testado em Linux (Arch). Outros sistemas podem exigir ajustes

---

## 🎯 Roadmap (futuro)

* Histórico de análises
* Exportação de relatório
* Mapeamento MITRE ATT&CK
* Autenticação e perfis de analista
* Integração com SIEM

---

**SOCINTEL — OSINT Tool**
