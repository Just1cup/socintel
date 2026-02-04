# SOCINTEL — Guia Windows (passo a passo)

Este documento descreve como preparar o ambiente, executar em modo desenvolvimento (não compilado) e opções de empacotamento (compilado) no Windows.

## Pré-requisitos
- Windows 10/11
- Python 3.10+ instalado
- Node.js + npm
- Git

## 1) Criar e ativar virtualenv (venv)
Abra PowerShell na raiz do repositório (`c:\Programação\sei lá\socintel`):

```powershell
# criar venv
python -m venv .venv

# ativar (PowerShell)
.\.venv\Scripts\Activate.ps1

# atualizar pip
python -m pip install -U pip setuptools
```

## 2) Instalar dependências Python
No venv ativado, instale as bibliotecas necessárias:

```powershell
python -m pip install requests beautifulsoup4 dnspython python-whois python-dotenv
```

Opcional (para empacotar):

```powershell
python -m pip install pyinstaller
```

## 3) Instalar dependências do frontend

```powershell
cd frontend
npm install
cd ..
```

## 4) Configurar variáveis de ambiente (API keys)
Crie um arquivo `.env` no backend com as chaves necessárias:

```
VT_API_KEY=your_virustotal_api_key
ABUSE_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_otx_key
```

## 5) Executar em modo desenvolvimento (não compilado)
Com o venv ativo, rode o Electron (a partir da raiz do projeto):

```powershell
npm start
```

O frontend usa o Python do venv (preload já aponta para `.venv\Scripts\python.exe`).

Teste direto no backend:

```powershell
.\.venv\Scripts\python.exe backend\socintel.py --domain example.com --json
```

## 6) Empacotar / Compilar
### Backend (opção): gerar exe com PyInstaller

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install pyinstaller
python -m PyInstaller --onefile backend\socintel.py
# exe em dist\socintel.exe
```

### Frontend (opção): empacotar Electron com electron-builder
1. Instalar `electron-builder` no `frontend`:

```powershell
cd frontend
npm install --save-dev electron-builder
```

2. Adicionar script `build` em `frontend/package.json` e configurar `build` se necessário.

3. Rodar:

```powershell
npm run build
```

> Observação: Para distribuir uma versão integrada você precisará incluir o executável do backend no pacote do Electron ou alterar `preload.js` para apontar para o executável distribuído.

## 7) Fontes de inteligência usadas
- VirusTotal
- AbuseIPDB
- AlienVault OTX
- URLhaus
- Any.run (links)
- RDAP (ARIN/RIPE/APNIC/LACNIC)
- WHOIS via socket (porta 43)
- DNS (MX/SOA)
- MAC Vendors (api.macvendors)
- SiteConfiavel (scraping)

## 8) Troubleshooting rápido
- `No module named 'bs4'` → instale `beautifulsoup4` no venv
- `O sistema não pode encontrar o caminho especificado` → verifique `.venv\Scripts\python.exe` e `preload.js`
- Use `python -m pip install ...` se `pip` não for reconhecido