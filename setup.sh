#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_PARENT="$(cd "${ROOT_DIR}/.." && pwd)"
OUT_ROOT="${ROOT_PARENT}/Socintel - V1"
STAGE_DIR="${OUT_ROOT}/stage"
BUILD_DIR="${OUT_ROOT}/.build"
DIST_DIR="${OUT_ROOT}/dist"
BACKEND_DIST="${DIST_DIR}/backend"
FRONTEND_DIST="${DIST_DIR}/frontend"
RELEASE_ROOT="${OUT_ROOT}"
RELEASE_DIR="${OUT_ROOT}/dist/release"
LOG_DIR="${OUT_ROOT}/logs"
BUILD_LOG="${LOG_DIR}/build.log"
VERSION="1.0.0"
RELEASE_NAME="socintel-v${VERSION}-linux-x64"

REQS_SRC="${ROOT_DIR}/requirements.txt"
REQS_CLEAN="${BUILD_DIR}/requirements.utf8.txt"

usage() {
  cat <<USAGE
Uso:
  ./setup.sh deps   # instala dependências (Arch)
  ./setup.sh build  # build de desenvolvimento (gera bundle)
  ./setup.sh release  # build final (release)
  ./setup.sh clean  # limpa artefatos
USAGE
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

preflight_arch() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Este build é suportado apenas em Linux."
    exit 1
  fi
  local missing=()
  for cmd in python3 pip node npm git zip patchelf; do
    if ! need_cmd "$cmd"; then
      missing+=("$cmd")
    fi
  done

  if (( ${#missing[@]} > 0 )); then
    echo "Faltando ferramentas: ${missing[*]}"
    echo "Instale com: sudo pacman -S --needed python python-pip nodejs npm git zip patchelf"
    exit 1
  fi
}

sanitize_requirements() {
  mkdir -p "$BUILD_DIR"
  if file -b "$REQS_SRC" | grep -qi "UTF-16"; then
    iconv -f UTF-16LE -t UTF-8 "$REQS_SRC" | tr -d '\r' > "$REQS_CLEAN"
  else
    tr -d '\r' < "$REQS_SRC" > "$REQS_CLEAN"
  fi
}

prepare_stage() {
  rm -rf "$STAGE_DIR"
  mkdir -p "$STAGE_DIR"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a \
      --exclude ".git" \
      --exclude ".build" \
      --exclude "dist" \
      --exclude "node_modules" \
      --exclude "frontend/node_modules" \
      --exclude "backend/.env" \
      --exclude "backend/logs" \
      "$ROOT_DIR/" "$STAGE_DIR/"
  else
    cp -R "$ROOT_DIR/" "$STAGE_DIR/"
    rm -rf "$STAGE_DIR/.git" "$STAGE_DIR/.build" "$STAGE_DIR/dist" \
      "$STAGE_DIR/node_modules" "$STAGE_DIR/frontend/node_modules" \
      "$STAGE_DIR/backend/.env" "$STAGE_DIR/backend/logs"
  fi
}

init_logging() {
  mkdir -p "$LOG_DIR"
  touch "$BUILD_LOG"
  exec > >(tee -a "$BUILD_LOG") 2>&1
  echo "==> Build log: $BUILD_LOG"
}

build_backend() {
  echo "==> Build backend (PyInstaller onedir)"
  local venv_dir="${BUILD_DIR}/venv-build"
  if [[ ! -d "$venv_dir" ]]; then
    python3 -m venv "$venv_dir"
  fi
  # shellcheck disable=SC1091
  source "$venv_dir/bin/activate"

  sanitize_requirements
  pip install --upgrade pip
  pip install -r "$REQS_CLEAN"
  # Pin versions known to work with PyInstaller on Arch/Python 3.14
  pip install "pyinstaller==6.18.0" "altgraph==0.17.4"

  rm -rf "$BACKEND_DIST" "${BUILD_DIR}/pyinstaller" "${BUILD_DIR}/pyinstaller.log"
  mkdir -p "$BACKEND_DIST"
  pyinstaller \
    --noconfirm \
    --clean \
    --onedir \
    --name socintel-backend \
    --distpath "$BACKEND_DIST" \
    --specpath "$BUILD_DIR" \
    --workpath "${BUILD_DIR}/pyinstaller" \
    --log-level INFO \
    "$STAGE_DIR/backend/socintel.py" 2>&1 | tee "${BUILD_DIR}/pyinstaller.log"

  if [[ ! -x "${BACKEND_DIST}/socintel-backend/socintel-backend" && ! -x "${BACKEND_DIST}/socintel-backend" ]]; then
    echo "Build do backend falhou. Veja o log em: ${BUILD_DIR}/pyinstaller.log"
    exit 1
  fi

  deactivate
}

build_frontend() {
  echo "==> Build frontend (Electron)"
  rm -rf "$FRONTEND_DIST"
  NODE_ENV=production npm ci --prefix "$STAGE_DIR/frontend"

  # Ensure electron version is fixed for electron-builder
  local ev
  ev=$(node -e "const p=process.argv[1]; const pkg=require(p); const v=(pkg.devDependencies && pkg.devDependencies.electron) || (pkg.dependencies && pkg.dependencies.electron) || ''; console.log(String(v).replace(/^[^0-9]*/, ''));" "$STAGE_DIR/frontend/package.json" || true)
  if [[ -n "${ev:-}" ]]; then
    export ELECTRON_VERSION="$ev"
  fi

  # Prefer electron-builder if available; fallback to electron-packager
  if need_cmd npx; then
    if npx --yes electron-builder --version >/dev/null 2>&1; then
      npx --yes electron-builder --linux --x64 --dir --projectDir "$STAGE_DIR/frontend" --config.directories.output="$FRONTEND_DIST"
    else
      npx --yes electron-packager "$STAGE_DIR/frontend" socintel --platform=linux --arch=x64 --out "$FRONTEND_DIST" --overwrite
    fi
  else
    echo "npx não encontrado. Instale node/npm corretamente."
    exit 1
  fi
}

write_release_files() {
  local release_root="${RELEASE_DIR}/${RELEASE_NAME}"
  local backend_out="${BACKEND_DIST}/socintel-backend"

  mkdir -p "$release_root/bin" "$release_root/app" "$release_root/logs" "$RELEASE_ROOT/config"

  # Backend binary
  if [[ -x "${backend_out}/socintel-backend" ]]; then
    cp -R "${backend_out}" "$release_root/bin/"
  elif [[ -x "${backend_out}" ]]; then
    cp "${backend_out}" "$release_root/bin/"
  else
    echo "Backend binário não encontrado em ${backend_out}"
    exit 1
  fi

  # Frontend package
  cp -R "$FRONTEND_DIST"/* "$release_root/app/"

  # Launcher
  cat <<'RUN' > "$release_root/run.sh"
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$APP_DIR/bin"
LOG_DIR="$APP_DIR/logs"
RUN_LOG="$LOG_DIR/run.log"

mkdir -p "$LOG_DIR"
touch "$RUN_LOG"

log() {
  local msg="$1"
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" | tee -a "$RUN_LOG"
}

ENV_CANDIDATES=(
  "$APP_DIR/../config/.env"
  "$APP_DIR/.env"
  "$APP_DIR/backend/.env"
)

if [[ -n "${SOCINTEL_ENV:-}" && -f "$SOCINTEL_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$SOCINTEL_ENV"
  set +a
  log "ENV carregado via SOCINTEL_ENV=$SOCINTEL_ENV"
else
  for f in "${ENV_CANDIDATES[@]}"; do
    if [[ -f "$f" ]]; then
      set -a
      # shellcheck disable=SC1090
      source "$f"
      set +a
      log "ENV carregado de $f"
      break
    fi
  done
fi

export SOCINTEL_LOG_DIR="$LOG_DIR"
export ELECTRON_ENABLE_LOGGING=1
export ELECTRON_ENABLE_STACK_DUMPING=1

if [[ -x "$BACKEND_DIR/socintel-backend/socintel-backend" ]]; then
  export SOCINTEL_BACKEND="$BACKEND_DIR/socintel-backend/socintel-backend"
  log "Backend binário: $SOCINTEL_BACKEND"
elif [[ -x "$BACKEND_DIR/socintel-backend" ]]; then
  export SOCINTEL_BACKEND="$BACKEND_DIR/socintel-backend"
  log "Backend binário: $SOCINTEL_BACKEND"
else
  # Fallback: search for backend in parent dist/backend (dev/test builds)
  backend_fallback=$(find "$APP_DIR/../.." -path "*/dist/backend/socintel-backend/socintel-backend" -type f -perm -111 2>/dev/null | head -n 1 || true)
  if [[ -n "${backend_fallback:-}" ]]; then
    export SOCINTEL_BACKEND="$backend_fallback"
    log "Backend binário (fallback): $SOCINTEL_BACKEND"
  else
    log "Backend binário não encontrado em $BACKEND_DIR"
  fi
fi

# Start Electron app (linux-unpacked, packager, or AppImage)
if [[ -x "$APP_DIR/app/linux-unpacked/socintel-ui" ]]; then
  log "Iniciando frontend: linux-unpacked/socintel-ui"
  "$APP_DIR/app/linux-unpacked/socintel-ui" >>"$RUN_LOG" 2>&1
elif [[ -x "$APP_DIR/app/linux-unpacked/socintel" ]]; then
  log "Iniciando frontend: linux-unpacked/socintel"
  "$APP_DIR/app/linux-unpacked/socintel" >>"$RUN_LOG" 2>&1
elif [[ -x "$APP_DIR/app/SOCINTEL" ]]; then
  log "Iniciando frontend: app/SOCINTEL"
  "$APP_DIR/app/SOCINTEL" >>"$RUN_LOG" 2>&1
elif [[ -x "$APP_DIR/app/socintel" ]]; then
  log "Iniciando frontend: app/socintel"
  "$APP_DIR/app/socintel" >>"$RUN_LOG" 2>&1
else
  appimage=$(find "$APP_DIR/app" -maxdepth 2 -type f -name "*.AppImage" | head -n 1 || true)
  if [[ -n "${appimage:-}" ]]; then
    chmod +x "$appimage"
    log "Iniciando frontend: AppImage $appimage"
    "$appimage" >>"$RUN_LOG" 2>&1
  else
    # fallback: first executable in app/*/* (electron-packager)
    candidate=$(find "$APP_DIR/app" -maxdepth 2 -type f -perm -111 | head -n 1 || true)
    if [[ -n "${candidate:-}" ]]; then
      log "Iniciando frontend: $candidate"
      "$candidate" >>"$RUN_LOG" 2>&1
    else
      log "Executável Electron não encontrado em $APP_DIR/app"
      exit 1
    fi
  fi
fi
RUN
  chmod +x "$release_root/run.sh"

  # Deploy README
  cat <<README > "$release_root/README_DEPLOY.md"
# SOCINTEL v${VERSION} (Linux x64)

## Como rodar
1. Extraia o zip
2. (Opcional) Crie um .env ao lado do run.sh com as chaves de API
3. Execute:

\`\`\`bash
./run.sh
\`\`\`

## Logs
Os logs ficam em \`./logs/\`.

## Variáveis suportadas
- \`SOCINTEL_ENV\`: caminho para arquivo .env externo
- \`SOCINTEL_BACKEND\`: caminho para binário do backend (override)
- \`SOCINTEL_LOG_DIR\`: diretório de logs
README
}

bundle_release() {
  echo "==> Bundling release"
  rm -rf "$RELEASE_DIR"
  mkdir -p "$RELEASE_DIR"
  write_release_files

  local release_root="${RELEASE_DIR}/${RELEASE_NAME}"
  local zip_path="${RELEASE_DIR}/${RELEASE_NAME}.zip"

  (cd "$RELEASE_DIR" && zip -r "${zip_path}" "${RELEASE_NAME}")
  (cd "$RELEASE_DIR" && sha256sum "${RELEASE_NAME}.zip" > "${RELEASE_NAME}.zip.sha256")

  echo "Release pronta em: $release_root"
  echo "Artefatos: $zip_path e ${zip_path}.sha256"
}

clean_all() {
  rm -rf "$OUT_ROOT" "$ROOT_DIR/node_modules" "$ROOT_DIR/frontend/node_modules"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    deps)
      sudo pacman -S --needed python python-pip nodejs npm git zip patchelf
      ;;
    build)
      preflight_arch
      init_logging
      prepare_stage
      build_backend
      build_frontend
      bundle_release
      ;;
    release)
      preflight_arch
      init_logging
      prepare_stage
      build_backend
      build_frontend
      bundle_release
      # keep only final artifacts
      rm -rf "$STAGE_DIR" "$BUILD_DIR" "$DIST_DIR/backend" "$DIST_DIR/frontend"
      ;;
    clean)
      clean_all
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
