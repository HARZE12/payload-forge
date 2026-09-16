#!/usr/bin/env bash
# ============================================================================
#  offsec-setup.sh — one-shot offensive tooling installer for Omarchy / Arch
# ============================================================================
#  Downloads & installs everything into YOUR terminal, natively:
#    * official Arch repos (pacman)
#    * AUR packages (yay / paru, auto-built if missing)
#    * GitHub release binaries (chisel, linpeas, pspy, …)
#    * git clones (PayloadsAllTheThings, …) + wordlists (rockyou)
#
#  USAGE
#    ./offsec-setup.sh                    # everything (all categories)
#    ./offsec-setup.sh --yes              # fully non-interactive
#    ./offsec-setup.sh recon web ad       # only these categories
#    ./offsec-setup.sh --tool ffuf        # one specific tool
#    ./offsec-setup.sh --list             # show everything, install nothing
#    ./offsec-setup.sh --update           # upgrade AUR pkgs + clones + bins
#    ./offsec-setup.sh --no-aur           # official repos only
#    ./offsec-setup.sh --no-bin           # skip GitHub release binaries
#    ./offsec-setup.sh --tools-dir ~/ot   # where clones/bins/wordlists go
#    ./offsec-setup.sh --add-path         # add bins dir to your shell rc
#
#  !!  LEGAL DISCLAIMER  !!
#  These are offensive tools. Use ONLY on systems you own or have explicit
#  written authorization to test. Unauthorized use is illegal in most
#  jurisdictions. You are responsible for your own actions.
# ============================================================================
set -Eeuo pipefail

# ----------------------------- config --------------------------------------
TOOLS_DIR="${HOME}/offsec-tools"
ASSUME_YES=0
NO_AUR=0
NO_BIN=0
ADD_PATH=0
DO_UPDATE=0
LIST_ONLY=0
VERBOSE=0
SELECTED=()
PER_TOOL=()
LOG_FILE="${LOG_FILE:-$HOME/.cache/offsec-setup.log}"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || LOG_FILE="/tmp/offsec-setup.log"

# ----------------------------- pretty --------------------------------------
if [ -t 1 ]; then
  C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_R=$'\033[1;31m'; C_B=$'\033[1;34m'; C_0=$'\033[0m'
else
  C_G=""; C_Y=""; C_R=""; C_B=""; C_0=""
fi
info()  { printf '%s[*]%s %s\n' "$C_B" "$C_0" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_G" "$C_0" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_Y" "$C_0" "$*"; }
err()   { printf '%s[x]%s %s\n' "$C_R" "$C_0" "$*" >&2; }
vlog()  { [ "$VERBOSE" -eq 1 ] && printf '    … %s\n' "$*" >&2; return 0; }

INSTALLED=(); SKIPPED=(); FAILED=()

# ----------------------- tool registry (curated) ---------------------------
# Auto-routing: official repo -> pacman, otherwise -> AUR helper.
# Non-package items live in BIN_INSTALLS / GIT_CLONES below.
CORE_PKGS=(git curl wget unzip tar gzip jq base-devel libpcap)
NATIVE_CATEGORIES=(core recon web net wifi ad exploit password tunnel forensics extras)

RECON_PKGS=(nmap masscan rustscan amass theharvester-git subfinder naabu httpx)
WEB_PKGS=(ffuf feroxbuster gobuster dirsearch sqlmap nikto whatweb wfuzz \
          wafw00f testssl.sh-git mitmproxy burpsuite seclists)
NET_PKGS=(bettercap wireshark-qt tcpdump)
WIFI_PKGS=(aircrack-ng wifite hcxtools hcxdumptool)
AD_PKGS=(impacket netexec responder python-certipy-ad-git python-dnsrecon)
EXPLOIT_PKGS=(exploitdb metasploit-git)
PASSWORD_PKGS=(john hashcat seclists)
TUNNEL_PKGS=(ligolo-ng)
FORENSICS_PKGS=(radare2 binwalk)
EXTRAS_PKGS=(go pipx)

BIN_INSTALLS=(
  # name|owner/repo|asset-regex|filename
  "chisel|jpillora/chisel|chisel_.*_linux_amd64\\.gz$|chisel"
  "linpeas|peass-ng/PEASS-ng|linpeas\\.sh$|linpeas.sh"
  "pspy|DominicBreuker/pspy|pspy64$|pspy64"
)

GIT_CLONES=(
  # name|repo-url
  "PayloadsAllTheThings|https://github.com/swisskyrepo/PayloadsAllTheThings"
)

# canonical category -> packages (single source of truth; order = NATIVE_CATEGORIES)
category_pkgs() {
  case "$1" in
    core)      printf '%s\n' "${CORE_PKGS[@]}" ;;
    recon)     printf '%s\n' "${RECON_PKGS[@]}" ;;
    web)       printf '%s\n' "${WEB_PKGS[@]}" ;;
    net)       printf '%s\n' "${NET_PKGS[@]}" ;;
    wifi)      printf '%s\n' "${WIFI_PKGS[@]}" ;;
    ad)        printf '%s\n' "${AD_PKGS[@]}" ;;
    exploit)   printf '%s\n' "${EXPLOIT_PKGS[@]}" ;;
    password)  printf '%s\n' "${PASSWORD_PKGS[@]}" ;;
    tunnel)    printf '%s\n' "${TUNNEL_PKGS[@]}" ;;
    forensics) printf '%s\n' "${FORENSICS_PKGS[@]}" ;;
    extras)    printf '%s\n' "${EXTRAS_PKGS[@]}" ;;
    *) return 1 ;;
  esac
}

# alias -> canonical category (normalized in one place)
normalize_category() {
  case "$1" in
    recon|reconnaissance)        printf 'recon' ;;
    web)                         printf 'web' ;;
    net|network)                 printf 'net' ;;
    wifi|wireless)               printf 'wifi' ;;
    ad|domain|windows)           printf 'ad' ;;
    exploit)                     printf 'exploit' ;;
    password|passwords|cracking) printf 'password' ;;
    tunnel|tunnels|pivoting)     printf 'tunnel' ;;
    forensics|reversing)         printf 'forensics' ;;
    extras)                      printf 'extras' ;;
    core)                        printf 'core' ;;
    *) return 1 ;;
  esac
}

# ----------------------------- helpers -------------------------------------
usage() {
  cat <<'EOF'
offsec-setup.sh — one-shot offensive tooling installer for Omarchy / Arch

Downloads & installs everything into YOUR terminal, natively:
  * official Arch repos (pacman)
  * AUR packages (yay / paru, auto-built if missing)
  * GitHub release binaries (chisel, linpeas, pspy, ...)
  * git clones (PayloadsAllTheThings, ...) + wordlists (rockyou)

USAGE
  ./offsec-setup.sh                    everything (all categories)
  ./offsec-setup.sh --yes              fully non-interactive
  ./offsec-setup.sh recon web ad       only these categories
  ./offsec-setup.sh --tool ffuf        one specific tool
  ./offsec-setup.sh --list             show everything, install nothing
  ./offsec-setup.sh --update           upgrade AUR pkgs + clones + bins
  ./offsec-setup.sh --no-aur           official repos only
  ./offsec-setup.sh --no-bin           skip GitHub release binaries
  ./offsec-setup.sh --tools-dir ~/ot   where clones/bins/wordlists go
  ./offsec-setup.sh --add-path         add bins dir to your shell rc

CATEGORIES
  recon  web  net  wifi  ad  exploit  password  tunnel  forensics  extras
  aliases: network, wireless, domain, windows, cracking, pivoting, ...

!!  LEGAL DISCLAIMER  !!
Use ONLY on systems you own or have explicit written authorization to test.
EOF
  exit 0
}

need_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    err "Do not run this script as root. Run as your normal user; sudo is used internally."
    exit 1
  fi
  command -v sudo >/dev/null 2>&1 || { err "sudo not found"; exit 1; }
  sudo -v || { err "sudo authentication failed"; exit 1; }
}

pkg_installed() { pacman -Qi "$1" >/dev/null 2>&1; }
in_official_repo() { pacman -Si "$1" >/dev/null 2>&1; }

aur_helper() {
  for h in yay paru; do command -v "$h" >/dev/null 2>&1 && { printf '%s' "$h"; return 0; }; done
  return 1
}

ensure_aur_helper() {
  [ "$NO_AUR" -eq 1 ] && return 1
  aur_helper && return 0
  warn "No AUR helper found — building yay from source (one-time, ~1 min)…"
  local src="${TOOLS_DIR}/git/yay"
  mkdir -p "$src"
  if [ ! -d "$src/.git" ]; then
    git clone --depth 1 https://aur.archlinux.org/yay.git "$src" || return 1
  fi
  ( cd "$src" && makepkg -si --needed --noconfirm ) || return 1
  command -v yay >/dev/null 2>&1
}

# route_install <pkg>  → 0 installed now, 1 skipped (already present), 2 failed
route_install() {
  local pkg="$1"
  if pkg_installed "$pkg"; then vlog "$pkg already installed"; return 1; fi
  if in_official_repo "$pkg"; then
    vlog "installing $pkg (official repo)"
    if [ "$ASSUME_YES" -eq 1 ]; then sudo pacman -S --needed --noconfirm "$pkg"
    else sudo pacman -S --needed "$pkg"; fi
    return 0
  fi
  local helper
  if helper="$(aur_helper)"; then
    vlog "installing $pkg (AUR via $helper)"
    if [ "$ASSUME_YES" -eq 1 ]; then "$helper" -S --needed --noconfirm "$pkg"
    else "$helper" -S --needed "$pkg"; fi
    return 0
  fi
  err "$pkg not in official repos and no AUR helper available"
  return 2
}

install_category() {
  local cat="$1" pkg rc
  printf '\n%s── %s ──────────────────────────────%s\n' "$C_B" "$cat" "$C_0"
  while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    if route_install "$pkg"; then
      ok "$pkg installed"; INSTALLED+=("$pkg")
    else
      rc=$?
      if [ "$rc" -eq 1 ]; then vlog "$pkg already present — skipped"; SKIPPED+=("$pkg")
      else err "$pkg FAILED (see log)"; FAILED+=("$pkg"); fi
    fi
  done < <(category_pkgs "$cat")
}

# gh_install_bin name|owner/repo|asset-regex|filename
gh_install_bin() {
  local spec="$1" name repo regex fname dest url tmp tag
  IFS='|' read -r name repo regex fname <<<"$spec"
  dest="${TOOLS_DIR}/bin/${fname}"
  if [ -x "$dest" ] && [ -f "${dest}.tag" ]; then
    tag="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
           | jq -r '.tag_name' 2>/dev/null || true)"
    if [ -n "$tag" ] && [ "$tag" = "$(cat "${dest}.tag")" ]; then
      vlog "$name up to date ($tag)"; SKIPPED+=("$name"); return 0
    fi
  fi
  vlog "fetching $name latest release from $repo"
  url="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
        | jq -r '.assets[].browser_download_url' 2>/dev/null \
        | grep -E "$regex" | head -1)"
  if [ -z "$url" ]; then
    err "$name: no matching release asset (${regex})"; return 2
  fi
  tmp="$(mktemp -d)"
  curl -fL --retry 3 -o "${tmp}/dl" "$url" || { rm -rf "$tmp"; return 2; }
  mkdir -p "${TOOLS_DIR}/bin"
  case "$url" in
    *.tar.gz|*.tgz)
      tar -xzf "${tmp}/dl" -C "$tmp" || { rm -rf "$tmp"; return 2; }
      local found=0 f
      while IFS= read -r f; do
        if [ -f "$f" ] && [ -x "$f" ]; then found=1; break; fi
      done < <(find "$tmp" -type f -perm -u+x)
      [ "$found" -eq 1 ] || { rm -rf "$tmp"; return 2; }
      install -m 0755 "$f" "$dest"
      ;;
    *.gz)
      mv "${tmp}/dl" "${tmp}/dl.gz"
      gunzip -f "${tmp}/dl.gz" || { rm -rf "$tmp"; return 2; }
      install -m 0755 "${tmp}/dl" "$dest"
      ;;
    *)
      install -m 0755 "${tmp}/dl" "$dest"
      ;;
  esac
  tag="$(printf '%s' "$url" | sed -E 's#.*/releases/download/([^/]+)/.*#\1#')"
  printf '%s' "$tag" > "${dest}.tag"
  rm -rf "$tmp"
  ok "$name → $dest ($tag)"
  INSTALLED+=("$name")
  return 0
}

git_clone() {
  local spec="$1" name url dir
  IFS='|' read -r name url <<<"$spec"
  dir="${TOOLS_DIR}/git/${name}"
  if [ -d "$dir/.git" ]; then
    git -C "$dir" pull --ff-only >/dev/null 2>&1 && vlog "$name repo updated" \
      || warn "$name repo pull failed (local changes?)"
    SKIPPED+=("$name")
  else
    git clone --depth 1 "$url" "$dir" || return 2
    ok "$name → $dir"; INSTALLED+=("$name")
  fi
  return 0
}

install_wordlists() {
  local dir="${TOOLS_DIR}/wordlists" f
  mkdir -p "$dir"
  f="${dir}/rockyou.txt"
  if [ -s "$f" ]; then vlog "rockyou.txt present"; return 0; fi
  info "Downloading rockyou.txt (~130 MB)…"
  curl -fL --retry 3 -o "$f" \
    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
    && ok "rockyou.txt → $f" && INSTALLED+=("rockyou.txt") \
    || { err "rockyou.txt download failed"; FAILED+=("rockyou.txt"); }
}

do_install() {
  local cat spec
  info "Refreshing databases + upgrading installed packages (pacman -Syu)…"
  if [ "$ASSUME_YES" -eq 1 ]; then
    sudo pacman -Syu --needed --noconfirm
  else
    sudo pacman -Syu --needed
  fi
  for cat in "${SELECTED[@]}"; do install_category "$cat"; done
  # single-tool runs skip the heavyweight extras (rockyou, clones, all bins)
  if [ "${TOOL_ONLY:-0}" -eq 1 ]; then return 0; fi
  if [ "$NO_BIN" -eq 0 ]; then
    for spec in "${BIN_INSTALLS[@]}"; do
      gh_install_bin "$spec" || FAILED+=("$(printf '%s' "$spec" | cut -d'|' -f1)")
    done
  fi
  if [ "$NO_AUR" -eq 0 ]; then
    for spec in "${GIT_CLONES[@]}"; do
      git_clone "$spec" || FAILED+=("$(printf '%s' "$spec" | cut -d'|' -f1)")
    done
  fi
  install_wordlists
}

do_update() {
  info "Updating official packages…"
  if [ "$ASSUME_YES" -eq 1 ]; then sudo pacman -Syu --noconfirm || true
  else sudo pacman -Syu || true; fi
  info "Updating AUR packages installed by this script…"
  local helper pkg
  if helper="$(aur_helper)"; then
    while IFS= read -r pkg; do
      pacman -Qi "$pkg" >/dev/null 2>&1 || continue
      pacman -Qm "$pkg" >/dev/null 2>&1 || continue   # foreign => AUR
      vlog "upgrading AUR pkg: $pkg"
      if [ "$ASSUME_YES" -eq 1 ]; then "$helper" -S --needed --noconfirm "$pkg" || true
      else "$helper" -S --needed "$pkg" || true; fi
    done < <(category_pkgs_all)
  else
    warn "no AUR helper; skipping AUR upgrades"
  fi
  info "Updating git tool clones…"
  local d
  for d in "${TOOLS_DIR}/git"/*/; do
    [ -d "$d/.git" ] && git -C "$d" pull --ff-only >/dev/null 2>&1 \
      && vlog "updated: $(basename "$d")"
  done
  info "Re-checking GitHub release binaries…"
  local spec
  for spec in "${BIN_INSTALLS[@]}"; do gh_install_bin "$spec" || true; done
  ok "update complete"
}

category_pkgs_all() {
  local cat
  for cat in "${NATIVE_CATEGORIES[@]}"; do category_pkgs "$cat"; done
}

add_path() {
  local line="export PATH=\"\$PATH:${TOOLS_DIR}/bin:\$HOME/.local/bin\""
  local touched=0 f
  for f in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$f" ] && ! grep -qF "offsec-tools/bin" "$f"; then
      printf '\n# added by offsec-setup.sh\n%s\n' "$line" >> "$f"
      ok "path added to $f"; touched=1
    fi
  done
  f="$HOME/.config/fish/config.fish"
  if [ -f "$f" ] && ! grep -qF "offsec-tools/bin" "$f"; then
    printf '\n# added by offsec-setup.sh\nfish_add_path -a %s %s\n' \
      "${TOOLS_DIR}/bin" "$HOME/.local/bin" >> "$f"
    ok "path added to $f"; touched=1
  fi
  [ "$touched" -eq 0 ] && info "nothing to add (or already present)"
  info "for this session run:  export PATH=\"\$PATH:${TOOLS_DIR}/bin:\$HOME/.local/bin\""
}

# selection: categories/aliases expand to categories; anything else must be a
# known tool name and installs that single tool (--tool ffuf == ffuf)
resolve_selection() {
  local per_tool=() arg norm cat found t
  for arg in "$@"; do
    if norm="$(normalize_category "$arg")"; then
      SELECTED+=("$norm")
    else
      per_tool+=("$arg")
    fi
  done
  if [ "${#per_tool[@]}" -gt 0 ]; then
    # validate names NOW — fail before any sudo prompt or system upgrade
    local bspec
    for t in "${per_tool[@]}"; do
      found=0
      for cat in "${NATIVE_CATEGORIES[@]}"; do
        category_pkgs "$cat" | grep -qxF "$t" && { found=1; break; }
      done
      for bspec in "${BIN_INSTALLS[@]}"; do
        [ "$found" -eq 1 ] && break
        [ "$t" = "$(printf '%s' "$bspec" | cut -d'|' -f1)" ] && found=1
      done
      if [ "$found" -eq 0 ]; then
        err "unknown category or tool: $t (see --list)"
        exit 2
      fi
    done
    PER_TOOL=("${per_tool[@]}")
  fi
  # dedupe categories, keep order
  local -a out=() seen=()
  local c s dup
  for c in "${SELECTED[@]+${SELECTED[@]}}"; do
    dup=0
    for s in "${seen[@]+${seen[@]}}"; do [ "$s" = "$c" ] && dup=1; done
    [ "$dup" -eq 0 ] && { out+=("$c"); seen+=("$c"); }
  done
  SELECTED=("${out[@]}")
  if [ "${#SELECTED[@]}" -eq 0 ] && [ "${#PER_TOOL[@]}" -eq 0 ]; then
    SELECTED=("${NATIVE_CATEGORIES[@]}")
  fi
}

install_per_tool() {
  local t cat rc bspec handled
  for t in "${PER_TOOL[@]}"; do
    handled=0
    # GitHub-bin tools install straight from releases
    for bspec in "${BIN_INSTALLS[@]}"; do
      if [ "$t" = "$(printf '%s' "$bspec" | cut -d'|' -f1)" ]; then
        printf '\n%s── tool: %s ──────────────────────%s\n' "$C_B" "$t" "$C_0"
        if gh_install_bin "$bspec"; then :;
        else FAILED+=("$t"); fi
        handled=1; break
      fi
    done
    [ "$handled" -eq 1 ] && continue
    for cat in "${NATIVE_CATEGORIES[@]}"; do
      if category_pkgs "$cat" | grep -qxF "$t"; then
        printf '\n%s── tool: %s ──────────────────────────%s\n' "$C_B" "$t" "$C_0"
        if route_install "$t"; then
          ok "$t installed"; INSTALLED+=("$t")
        else
          rc=$?
          if [ "$rc" -eq 1 ]; then vlog "$t already present — skipped"; SKIPPED+=("$t")
          else err "$t FAILED (see log)"; FAILED+=("$t"); fi
        fi
        break
      fi
    done
  done
}

summary() {
  printf '\n%s════════════ summary ════════════%s\n' "$C_B" "$C_0"
  printf '  installed: %s   skipped: %s   failed: %s\n' \
    "${#INSTALLED[@]}" "${#SKIPPED[@]}" "${#FAILED[@]}"
  if [ "${#FAILED[@]}" -gt 0 ]; then
    err "failed: ${FAILED[*]}  (log: $LOG_FILE)"
    return 1
  fi
  ok "tools dir: $TOOLS_DIR"
  ok "seclists:  /usr/share/seclists   wordlists: $TOOLS_DIR/wordlists"
  return 0
}

# ----------------------------- main ----------------------------------------
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then usage; fi

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)     ASSUME_YES=1 ;;
    -l|--list)    LIST_ONLY=1 ;;
    -u|--update)  DO_UPDATE=1 ;;
    -v|--verbose) VERBOSE=1 ;;
    --no-aur)     NO_AUR=1 ;;
    --no-bin)     NO_BIN=1 ;;
    --add-path)   ADD_PATH=1 ;;
    --tools-dir)  TOOLS_DIR="${2:?--tools-dir needs a value}"; shift ;;
    --tool)       [ -n "${2:-}" ] || { err "--tool needs a value"; exit 2; }
                  SELECTED+=("$2"); shift ;;
    --)           shift; break ;;
    -*)           err "unknown option: $1"; usage ;;
    *)            SELECTED+=("$1") ;;
  esac
  shift
done

exec > >(tee -a "$LOG_FILE") 2>&1

if [ "$LIST_ONLY" -eq 1 ]; then
  do_list() {
    local cat spec
    printf '%sPackages (official repo / AUR):%s\n' "$C_B" "$C_0"
    for cat in "${NATIVE_CATEGORIES[@]}"; do
      printf '  %-10s ' "$cat:"
      tr '\n' ' ' < <(category_pkgs "$cat"); printf '\n'
    done
    printf '%sGitHub release binaries:%s\n' "$C_B" "$C_0"
    for spec in "${BIN_INSTALLS[@]}"; do
      printf '  %-10s %s\n' "$(printf '%s' "$spec" | cut -d'|' -f1):" "$(printf '%s' "$spec" | cut -d'|' -f2)"
    done
    printf '%sGit clones:%s\n' "$C_B" "$C_0"
    for spec in "${GIT_CLONES[@]}"; do
      printf '  %-10s %s\n' "$(printf '%s' "$spec" | cut -d'|' -f1):" "$(printf '%s' "$spec" | cut -d'|' -f2)"
    done
    printf '  %-10s %s\n' "wordlists:" "rockyou.txt (+ seclists pkg)"
  }
  do_list
  exit 0
fi

resolve_selection "${SELECTED[@]}"
need_sudo

info "Omarchy/Arch offensive tooling setup"
info "targets: ${SELECTED[*]}${PER_TOOL[*]:+ + tools: ${PER_TOOL[*]}}"
info "tools dir: $TOOLS_DIR"
printf 'This installs ATTACK TOOLS. Use only on authorized systems. Continue? [y/N] '
if [ "$ASSUME_YES" -eq 1 ]; then
  printf 'y (auto)\n'
else
  read -r ans
  case "$ans" in y|Y|yes|Yes) ;; *) echo "aborted."; exit 1 ;; esac
fi

mkdir -p "${TOOLS_DIR}/git" "${TOOLS_DIR}/bin" "${TOOLS_DIR}/wordlists"
if ! ensure_aur_helper && [ "$NO_AUR" -eq 0 ]; then
  warn "proceeding without AUR support — AUR-only tools will fail"
fi

# core is an unconditional prerequisite (base-devel for AUR builds, jq, …)
SELECTED=("core" "${SELECTED[@]}")
# dedupe again in case user explicitly passed core
if [ "${SELECTED[1]:-}" = "core" ]; then
  SELECTED=("${SELECTED[@]:1}")
fi
TOOL_ONLY=0
[ "${#PER_TOOL[@]}" -gt 0 ] && [ "${#SELECTED[@]}" -le 1 ] && TOOL_ONLY=1

install_per_tool
do_install
[ "$ADD_PATH" -eq 1 ] && add_path

if summary; then
  printf '\n%sNext steps:%s\n' "$C_B" "$C_0"
  printf '  • searchsploit <query>        (exploit-db)\n'
  printf '  • nmap -sV -A <target>        (recon)\n'
  printf '  • netexec smb <dc-ip> -u user -p pass   (AD)\n'
  printf '  • linpeas/pspy: %s/bin   wordlists: %s/wordlists\n' "$TOOLS_DIR" "$TOOLS_DIR"
  if ! printf '%s' "$PATH" | grep -qF "$HOME/.local/bin"; then
    warn "~/.local/bin is not in PATH — re-run with --add-path or add it to your shell rc"
  fi
  exit 0
fi
exit 1
