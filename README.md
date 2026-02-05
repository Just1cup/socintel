# SOCINTEL

SOCINTEL é uma ferramenta OSINT/Threat Intelligence para SOC, com backend em Python e GUI em Electron.

## Visão prática
- Backend (CLI): análise de IP, domínio, endereço MAC, URL e email
- GUI (Electron): interface para executar análises e ver resultados
- Saída em JSON para integração

## Pré-requisitos
- Linux: `python3`, `pip3`, `node`, `npm`
- Windows: `python` e `pip` no PATH, `node`, `npm`

## Setup rápido 
Linux:
```bash
./setup.sh
```

Windows (PowerShell):
./setup.ps1 

Esses scripts:
1. Instalam as dependências Python do `requirements.txt`
2. Instalam as dependências do frontend (`npm install`)
3. Fazem um teste rápido do backend com `--ip 8.8.8.8`

## Uso via CLI
Exemplos:
```bash
python3 backend/socintel.py --ip 8.8.8.8
python3 backend/socintel.py --domain example.com
python3 backend/socintel.py --url https://example.com/login
python3 backend/socintel.py --email user@example.com
python3 backend/socintel.py --ip 8.8.8.8 --json
```

## Uso via GUI (Electron)
```bash
npm start
```

## Variáveis de ambiente
Crie `backend/.env` com as chaves de API:
```
VT_API_KEY=...
ABUSE_API_KEY=...
OTX_API_KEY=...
URLSCAN_API_KEY=...
URL_IO_KEY=...
```
As chaves devem ser colocadas logo após o símbolo de igual, mas NÂO de espaço.

Exemplo:

VT_API_KEY=1234
ABUSE_API_KEY=456
OTX_API_KEY=423
URLSCAN_API_KEY=1234
URL_IO_KEY=56567


## Build da GUI
```bash
npm install --save-dev electron-builder
npm run build
```

## Estrutura do projeto
```
socintel/
├── backend/
│   └── socintel.py
├── frontend/
│   ├── main.js
│   ├── preload.js
│   └── renderer.js
├── requirements.txt
├── setup.sh
└── setup.ps1
```

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
