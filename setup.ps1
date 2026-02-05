Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot ".")).Path

pip3 install -r (Join-Path $RootDir "requirements.txt")
npm install --prefix $RootDir
python3 (Join-Path $RootDir "backend\socintel.py") --ip 8.8.8.8
