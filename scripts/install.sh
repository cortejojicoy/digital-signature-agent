#!/usr/bin/env bash
# Kukux Sign Agent installer for macOS (https://cortejojicoy.github.io/digital-signature-agent/#/installation).
#
#   curl -fsSL https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.sh | bash
#   curl -fsSL …/install.sh | bash -s -- --version 1.2.0
#   ./install.sh --from ~/Downloads/kukux-sign-agent-1.2.0-mac-arm64.dmg
#   ./install.sh --uninstall [--purge]
#
# What it checks before installing anything:
#   1. the download's SHA-512 matches latest-mac.yml from the same release;
#   2. the bundle id, and that the app's code signature is intact
#      (codesign --strict; ad-hoc for free builds);
#   3. signed releases only: Developer ID + notarization (spctl) and, when
#      pinned, the Apple team id.
# Free releases (no paid Apple account) are ad-hoc signed; after the checks
# above the installer clears the quarantine flag so macOS opens the agent
# without a Gatekeeper prompt. Its keys still live in the Secure Enclave.
# Everything runs inside main(), so a truncated download executes nothing.
#
# Every step is logged to stderr: what it fetches, where it puts it, and
# what each check found.

set -euo pipefail

APP_NAME="Kukux Sign Agent"
BUNDLE_ID="com.kukux.signagent"
DEFAULT_RELEASES="https://github.com/cortejojicoy/digital-signature-agent/releases"
# Set by the release workflow: "true" for a Developer ID release, "false" for
# a free one. Left as the placeholder (script taken from the repository), the
# installer decides from the app itself.
RELEASE_SIGNED="${KUKUX_AGENT_RELEASE_SIGNED:-__KUKUX_RELEASE_SIGNED__}"
# Pinned by the release workflow for signed releases; override with KUKUX_AGENT_TEAM_ID.
EXPECTED_TEAM_ID="${KUKUX_AGENT_TEAM_ID:-__KUKUX_TEAM_ID__}"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
SETTINGS_DIR="$HOME/Library/Application Support/$APP_NAME"

if [ -t 2 ]; then
  BOLD=$'\033[1m' DIM=$'\033[2m' RED=$'\033[31m' GREEN=$'\033[32m' YELLOW=$'\033[33m' CYAN=$'\033[36m' RESET=$'\033[0m'
else
  BOLD="" DIM="" RED="" GREEN="" YELLOW="" CYAN="" RESET=""
fi
TICK="✓" CROSS="✗"

# All output goes to stderr. download() and extract() hand back their result
# in PACKAGE / APP instead of stdout, so they run in this shell and the step
# counter stays right.
STEP=0
STEPS=0
say() { printf '%s\n' "$*" >&2; }
step() {
  STEP=$((STEP + 1))
  printf '\n%s[%d/%d]%s %s%s%s\n' "$CYAN" "$STEP" "$STEPS" "$RESET" "$BOLD" "$*" "$RESET" >&2
}
# A labelled fact:     "      Into        /Applications/…"
info() { printf '        %s%-11s%s %s\n' "$DIM" "$1" "$RESET" "$2" >&2; }
# A check that passed: "      ✓ Bundle id   com.kukux.signagent"
ok() { printf '      %s%s%s %-11s %s\n' "$GREEN" "$TICK" "$RESET" "$1" "${2:-}" >&2; }
note() { printf '        %s%s%s\n' "$DIM" "$*" "$RESET" >&2; }
warn() { printf '      %s!%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die() {
  printf '\n%s%s error:%s %s\n' "$RED" "$CROSS" "$RESET" "$*" >&2
  exit 1
}

human_size() { awk -v b="$1" 'BEGIN { if (b >= 1048576) printf "%.1f MB", b / 1048576; else printf "%.0f KB", b / 1024 }'; }
dir_size() { human_size "$(($(du -sk "$1" 2>/dev/null | awk '{ print $1 }') * 1024))"; }
short_hash() { printf '%s…%s' "${1:0:12}" "${1: -8}"; }
plist_value() { /usr/libexec/PlistBuddy -c "Print $2" "$1/Contents/Info.plist" 2>/dev/null || true; }

usage() {
  cat <<EOF
Install Kukux Sign Agent on macOS.

Usage: install.sh [options]

  --version <x.y.z>   Install a specific version (default: latest)
  --base-url <url>    Download from a self-hosted release directory that
                      contains latest-mac.yml and the .zip files
  --from <file>       Install a local .zip or .dmg instead of downloading
  --dir <path>        Install into <path> (default: /Applications, or
                      ~/Applications if /Applications isn't writable)
  --allow-unsigned    Skip the code-signature checks entirely (your own
                      development builds only; the SHA-512 check still runs).
                      Not needed for free releases.
  --no-launch         Don't start the agent after installing
  --uninstall         Remove the agent (add --purge to delete its settings)
  -h, --help          Show this help

Environment: KUKUX_AGENT_VERSION, KUKUX_AGENT_BASE_URL, KUKUX_AGENT_INSTALL_DIR,
KUKUX_AGENT_ALLOW_UNSIGNED=1, KUKUX_AGENT_TEAM_ID, KUKUX_AGENT_RELEASE_SIGNED=true|false.
EOF
}

main() {
  local version="${KUKUX_AGENT_VERSION:-}"
  local base_url="${KUKUX_AGENT_BASE_URL:-}"
  local from=""
  local dir="${KUKUX_AGENT_INSTALL_DIR:-}"
  local allow_unsigned="${KUKUX_AGENT_ALLOW_UNSIGNED:-0}"
  local launch=1 uninstall=0 purge=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) version="${2:?--version needs a value}"; shift 2 ;;
      --base-url) base_url="${2:?--base-url needs a value}"; shift 2 ;;
      --from) from="${2:?--from needs a file}"; shift 2 ;;
      --dir) dir="${2:?--dir needs a path}"; shift 2 ;;
      --allow-unsigned) allow_unsigned=1; shift ;;
      --no-launch) launch=0; shift ;;
      --uninstall) uninstall=1; shift ;;
      --purge) purge=1; shift ;;
      -h | --help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done

  [ "$(uname -s)" = "Darwin" ] || die "this installer is for macOS; on Windows use install.ps1"

  if [ "$uninstall" = 1 ]; then
    do_uninstall "$purge"
    return
  fi

  local os_version major arch
  os_version="$(sw_vers -productVersion)"
  major="${os_version%%.*}"
  arch="$(detect_arch)"

  say "${BOLD}$APP_NAME installer${RESET}"
  info "This Mac" "macOS $os_version · $(arch_label "$arch")"
  if [ -n "$from" ]; then
    info "Source" "$from"
  elif [ -n "$version" ]; then
    info "Source" "${base_url:-$DEFAULT_RELEASES} (version ${version#v})"
  else
    info "Source" "${base_url:-$DEFAULT_RELEASES} (latest)"
  fi
  [ "$major" -ge 12 ] || die "macOS 12 or newer is required (this Mac runs $os_version)"

  # Release info + download + verify download, or just unpack a local file.
  if [ -n "$from" ]; then STEPS=3; else STEPS=6; fi
  [ "$launch" = 1 ] && STEPS=$((STEPS + 1))

  local tmp
  local tmp_base="${TMPDIR:-/tmp}"
  tmp="$(mktemp -d "${tmp_base%/}/kukux-agent.XXXXXX")"
  # shellcheck disable=SC2064
  trap "cleanup '$tmp'" EXIT

  if [ -n "$from" ]; then
    [ -f "$from" ] || die "no such file: $from"
    PACKAGE="$from"
  else
    download "$tmp" "$arch" "$version" "$base_url"
  fi

  extract "$tmp" "$PACKAGE"
  local app="$APP"
  verify_app "$app" "$allow_unsigned" "$version"

  local dir_reason=""
  if [ -z "$dir" ]; then
    dir="$(default_dir)"
    [ "$dir" = "/Applications" ] || dir_reason=" (/Applications isn't writable)"
  fi
  local dest="$dir/$APP_NAME.app"
  local new_version previous=""
  new_version="$(plist_value "$app" CFBundleShortVersionString)"
  [ -d "$dest" ] && previous="$(plist_value "$dest" CFBundleShortVersionString)"

  step "Installing"
  info "Into" "$dest$dir_reason"
  if [ -n "$previous" ]; then
    info "Replacing" "$previous → $new_version"
  else
    info "Version" "$new_version (new install)"
  fi
  mkdir -p "$dir"
  quit_running
  rm -rf "$dest"
  ditto "$app" "$dest" || die "could not copy the app to $dest"
  ok "Copied" "$APP_NAME.app ($(dir_size "$dest"))"
  # A free build isn't notarized, so a quarantine flag (set when the .dmg/.zip
  # came from a browser) would make Gatekeeper block it. It passed the checks
  # above, and you chose to install it.
  if [ "${FREE_BUILD:-0}" = 1 ]; then
    xattr -dr com.apple.quarantine "$dest" 2>/dev/null || true
    ok "Quarantine" "cleared, so macOS opens it without a Gatekeeper prompt"
  fi
  # Register the kukuxsign:// scheme now instead of on first launch.
  if [ -x "$LSREGISTER" ] && "$LSREGISTER" -f "$dest" >/dev/null 2>&1; then
    ok "Links" "kukuxsign:// now opens the agent"
  else
    note "kukuxsign:// links register on first launch"
  fi
  if [ -d "$SETTINGS_DIR" ]; then
    note "Kept your settings and paired apps in ~/Library/Application Support/$APP_NAME"
  fi

  if [ "$launch" = 1 ]; then
    step "Starting the agent"
    open "$dest"
    ok "Started" "it runs in the menu bar (look for the key icon)"
  fi

  say ""
  say "${GREEN}${TICK} $APP_NAME $new_version is installed.${RESET}"
  say ""
  say "Next: in the web app, open ${BOLD}My signing devices${RESET} → ${BOLD}Pair desktop agent${RESET},"
  say "then enter the address and code it shows in the agent."
  say "${DIM}Uninstall any time: curl -fsSL $DEFAULT_RELEASES/latest/download/install.sh | bash -s -- --uninstall${RESET}"
}

cleanup() {
  local tmp="$1"
  # Detach by path: the mount may be left over from a failed extract().
  if [ -d "$tmp/mnt" ]; then hdiutil detach -quiet "$tmp/mnt" 2>/dev/null || true; fi
  rm -rf "$tmp"
}

detect_arch() {
  local machine
  machine="$(uname -m)"
  # A shell running under Rosetta reports x86_64 on Apple silicon.
  if [ "$machine" = "x86_64" ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
    machine="arm64"
  fi
  case "$machine" in
    arm64) echo "arm64" ;;
    x86_64) echo "x64" ;;
    *) die "unsupported CPU: $machine" ;;
  esac
}

arch_label() {
  case "$1" in
    arm64) echo "Apple silicon (arm64)" ;;
    *) echo "Intel ($1)" ;;
  esac
}

default_dir() {
  if [ -w /Applications ]; then echo "/Applications"; else echo "$HOME/Applications"; fi
}

# curl options: HTTPS only, except http://localhost / 127.0.0.1 for testing
# a local release directory. A progress bar for big files on a terminal.
fetch() {
  local url="$1" out="$2" progress="${3:-0}"
  local proto="=https"
  case "$url" in http://localhost[:/]* | http://127.0.0.1[:/]*) proto="=http,https" ;; esac
  local quiet=(--silent)
  if [ "$progress" = 1 ] && [ -t 2 ]; then quiet=(--progress-bar); fi
  curl --fail --location "${quiet[@]}" --show-error --proto "$proto" --proto-redir "$proto" --retry 2 \
    --output "$out" "$url" || die "download failed: $url"
}

download() {
  local tmp="$1" arch="$2" version="$3" base_url="$4"
  if [ -z "$base_url" ]; then
    if [ -n "$version" ]; then
      base_url="$DEFAULT_RELEASES/download/v${version#v}"
    else
      base_url="$DEFAULT_RELEASES/latest/download"
    fi
  fi
  base_url="${base_url%/}"

  step "Reading the release"
  info "Metadata" "$base_url/latest-mac.yml"
  fetch "$base_url/latest-mac.yml" "$tmp/latest-mac.yml"

  # electron-builder metadata: "files:" entries of "- url:", "sha512:", "size:".
  local entry file sha size release_version release_date
  entry="$(awk -v want="-mac-$arch.zip" '
    /^[[:space:]]*-[[:space:]]*url:/ { if (found) exit; url = $NF; sha = ""; size = 0; next }
    /^[[:space:]]+sha512:/ { sha = $NF }
    /^[[:space:]]+size:/ { size = $NF }
    url != "" && index(url, want) && sha != "" { found = 1 }
    END { if (found) print url, sha, size }
  ' "$tmp/latest-mac.yml")"
  [ -n "$entry" ] || die "the release has no macOS $arch build"
  read -r file sha size <<<"$entry"
  release_version="$(awk '/^version:/ { print $2; exit }' "$tmp/latest-mac.yml" | tr -d "'\"")"
  release_date="$(awk '/^releaseDate:/ { print $2; exit }' "$tmp/latest-mac.yml" | tr -d "'\"" | cut -c1-10)"
  if [ -n "$version" ] && [ "${version#v}" != "$release_version" ]; then
    die "asked for $version but the release metadata is for $release_version"
  fi
  ok "Version" "$release_version${release_date:+ (released $release_date)}"
  ok "File" "$file ($(human_size "$size"))"

  step "Downloading"
  info "From" "$base_url/$file"
  info "To" "$tmp/$file"
  fetch "$base_url/$file" "$tmp/$file" 1
  ok "Downloaded" "$(human_size "$(stat -f%z "$tmp/$file")")"

  step "Checking the download"
  local actual
  actual="$(openssl dgst -sha512 -binary "$tmp/$file" | base64 | tr -d '\n')"
  info "Expected" "SHA-512 $(short_hash "$sha")"
  [ "$actual" = "$sha" ] || die "SHA-512 mismatch for $file (got $(short_hash "$actual")): the download is corrupt or was tampered with"
  ok "SHA-512" "$(short_hash "$actual") matches latest-mac.yml"
  PACKAGE="$tmp/$file"
}

extract() {
  local tmp="$1" package="$2"
  local out="$tmp/extracted"
  mkdir -p "$out"
  step "Unpacking"
  info "Package" "$package"
  case "$package" in
    *.zip)
      ditto -x -k "$package" "$out" || die "could not unzip $package"
      ;;
    *.dmg)
      local mnt="$tmp/mnt"
      mkdir -p "$mnt"
      hdiutil attach -quiet -nobrowse -readonly -mountpoint "$mnt" "$package" || die "could not open $package"
      note "mounted the disk image read-only"
      ditto "$mnt/$APP_NAME.app" "$out/$APP_NAME.app" || die "$APP_NAME.app not found in $package"
      hdiutil detach -quiet "$mnt" || true
      ;;
    *) die "expected a .zip or .dmg: $package" ;;
  esac
  [ -d "$out/$APP_NAME.app" ] || die "$APP_NAME.app not found in $package"
  ok "Unpacked" "$APP_NAME.app ($(dir_size "$out/$APP_NAME.app"))"
  APP="$out/$APP_NAME.app"
}

verify_app() {
  local app="$1" allow_unsigned="$2" wanted="$3"
  step "Checking the app"
  local id app_version
  id="$(plist_value "$app" CFBundleIdentifier)"
  [ "$id" = "$BUNDLE_ID" ] || die "unexpected bundle id '$id' (expected $BUNDLE_ID)"
  ok "Bundle id" "$id"
  app_version="$(plist_value "$app" CFBundleShortVersionString)"
  if [ -n "$wanted" ] && [ "${wanted#v}" != "$app_version" ]; then
    die "the app is version $app_version, expected ${wanted#v}"
  fi
  ok "Version" "${app_version:-?}"

  if [ "$allow_unsigned" = 1 ]; then
    warn "skipping signature checks (--allow-unsigned). Only do this for your own builds."
    FREE_BUILD=1
    return
  fi

  codesign --verify --deep --strict "$app" 2>/dev/null || die "the app's code signature is broken (damaged or modified download)"

  local signed="$RELEASE_SIGNED"
  case "$signed" in
    true | false) ;;
    *) if spctl --assess --type execute "$app" 2>/dev/null; then signed=true; else signed=false; fi ;;
  esac

  if [ "$signed" = false ]; then
    FREE_BUILD=1
    ok "Signature" "intact (ad-hoc: free build)"
    note "Not notarized by Apple (no paid developer account). Your keys still live in the Secure Enclave."
    return
  fi

  ok "Signature" "intact (Developer ID)"
  spctl --assess --type execute "$app" 2>/dev/null ||
    die "Gatekeeper rejected the app: this release should be signed with a Developer ID and notarized, but isn't"
  ok "Gatekeeper" "notarized by Apple"

  # Still the "__…__" placeholder means the release didn't pin a team id.
  case "$EXPECTED_TEAM_ID" in "" | __*__) EXPECTED_TEAM_ID="" ;; esac
  if [ -n "$EXPECTED_TEAM_ID" ]; then
    local team
    team="$(codesign -dv "$app" 2>&1 | awk -F= '/^TeamIdentifier=/ { print $2 }')"
    [ "$team" = "$EXPECTED_TEAM_ID" ] || die "signed by team '$team', expected $EXPECTED_TEAM_ID"
    ok "Team id" "$team"
  fi
}

quit_running() {
  pgrep -f "/$APP_NAME.app/Contents/MacOS/" >/dev/null 2>&1 || return 0
  info "Running" "the agent is open; quitting it first"
  osascript -e "tell application id \"$BUNDLE_ID\" to quit" >/dev/null 2>&1 || true
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if ! pgrep -f "/$APP_NAME.app/Contents/MacOS/" >/dev/null 2>&1; then
      ok "Quit" "the running agent"
      return 0
    fi
    sleep 0.5
  done
  pkill -f "/$APP_NAME.app/Contents/MacOS/" 2>/dev/null || true
  warn "the agent didn't quit in 5 s, so it was stopped"
}

do_uninstall() {
  local purge="$1" removed=0 dir
  STEPS=$((purge + 1))
  say "${BOLD}$APP_NAME uninstaller${RESET}"
  step "Removing the app"
  quit_running
  for dir in "/Applications" "$HOME/Applications" ${KUKUX_AGENT_INSTALL_DIR:+"$KUKUX_AGENT_INSTALL_DIR"}; do
    if [ -d "$dir/$APP_NAME.app" ]; then
      local old
      old="$(plist_value "$dir/$APP_NAME.app" CFBundleShortVersionString)"
      # Drop the kukuxsign:// registration along with the app.
      [ -x "$LSREGISTER" ] && "$LSREGISTER" -u "$dir/$APP_NAME.app" >/dev/null 2>&1 || true
      rm -rf "$dir/$APP_NAME.app" || die "could not remove $dir/$APP_NAME.app"
      ok "Removed" "$dir/$APP_NAME.app${old:+ ($old)}"
      removed=1
    fi
  done
  [ "$removed" = 1 ] || note "$APP_NAME is not installed."

  if [ "$purge" = 1 ]; then
    step "Removing settings"
    local path
    for path in "$SETTINGS_DIR" \
      "$HOME/Library/Preferences/$BUNDLE_ID.plist" \
      "$HOME/Library/Caches/$BUNDLE_ID" \
      "$HOME/Library/Caches/$BUNDLE_ID.ShipIt" \
      "$HOME/Library/Logs/$APP_NAME"; do
      if [ -e "$path" ]; then
        rm -rf "$path"
        ok "Removed" "${path/#$HOME/~}"
      fi
    done
    note "Paired apps, tokens and the agent's own key files are gone."
  else
    note "Kept your settings and paired apps (add --purge to remove them)."
  fi
  say ""
  say "If this computer was paired, revoke it in the web app under ${BOLD}My signing devices${RESET}."
  say "Its keys can't be used without the agent, and no other machine can use them."
}

main "$@"
