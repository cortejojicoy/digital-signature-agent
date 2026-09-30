#!/usr/bin/env bash
# Kukux Sign Agent installer for macOS (docs/installation.md).
#
#   curl -fsSL https://github.com/cortejojicoy/digital-signature-agent/releases/latest/download/install.sh | bash
#   curl -fsSL …/install.sh | bash -s -- --version 1.2.0
#   ./install.sh --from ~/Downloads/kukux-sign-agent-1.2.0-mac-arm64.dmg
#   ./install.sh --uninstall [--purge]
#
# What it checks before installing anything:
#   1. the download's SHA-512 matches latest-mac.yml from the same release;
#   2. the app is signed (codesign --strict), notarized (spctl) and has the
#      expected bundle id and, when pinned, Apple team id.
# Everything runs inside main(), so a truncated download executes nothing.

set -euo pipefail

APP_NAME="Kukux Sign Agent"
BUNDLE_ID="com.kukux.signagent"
DEFAULT_RELEASES="https://github.com/cortejojicoy/digital-signature-agent/releases"
# Pinned by the release workflow; override with KUKUX_AGENT_TEAM_ID.
EXPECTED_TEAM_ID="${KUKUX_AGENT_TEAM_ID:-__KUKUX_TEAM_ID__}"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

if [ -t 1 ]; then
  BOLD=$'\033[1m' DIM=$'\033[2m' RED=$'\033[31m' GREEN=$'\033[32m' RESET=$'\033[0m'
else
  BOLD="" DIM="" RED="" GREEN="" RESET=""
fi

say() { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$*"; }
die() {
  printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2
  exit 1
}

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
  --allow-unsigned    Skip the signature and notarization checks (development
                      builds only; the SHA-512 check still runs)
  --no-launch         Don't start the agent after installing
  --uninstall         Remove the agent (add --purge to delete its settings)
  -h, --help          Show this help

Environment: KUKUX_AGENT_VERSION, KUKUX_AGENT_BASE_URL, KUKUX_AGENT_INSTALL_DIR,
KUKUX_AGENT_ALLOW_UNSIGNED=1, KUKUX_AGENT_TEAM_ID.
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

  local major
  major="$(sw_vers -productVersion | cut -d. -f1)"
  [ "$major" -ge 12 ] || die "macOS 12 or newer is required (this Mac runs $(sw_vers -productVersion))"

  local arch
  arch="$(detect_arch)"

  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/kukux-agent.XXXXXX")"
  # shellcheck disable=SC2064
  trap "cleanup '$tmp'" EXIT

  local package
  if [ -n "$from" ]; then
    [ -f "$from" ] || die "no such file: $from"
    package="$from"
    step "Installing from $from"
  else
    package="$(download "$tmp" "$arch" "$version" "$base_url")"
  fi

  local app
  app="$(extract "$tmp" "$package")"
  verify_app "$app" "$allow_unsigned"

  [ -n "$dir" ] || dir="$(default_dir)"
  mkdir -p "$dir"
  local dest="$dir/$APP_NAME.app"

  quit_running
  step "Installing to $dest"
  rm -rf "$dest"
  ditto "$app" "$dest"
  # Register the kukuxsign:// scheme now instead of on first launch.
  [ -x "$LSREGISTER" ] && "$LSREGISTER" -f "$dest" >/dev/null 2>&1 || true

  local installed
  installed="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$dest/Contents/Info.plist" 2>/dev/null || echo "?")"
  say "${GREEN}Installed $APP_NAME $installed.${RESET}"

  if [ "$launch" = 1 ]; then
    open "$dest"
    say "It runs in the menu bar (look for the key icon)."
  fi
  say ""
  say "Next: in the web app, open ${BOLD}My signing devices${RESET} → ${BOLD}Pair desktop agent${RESET},"
  say "then enter the address and code it shows in the agent."
}

cleanup() {
  local tmp="$1"
  # extract() runs in a subshell, so detach by path rather than by variable.
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

default_dir() {
  if [ -w /Applications ]; then echo "/Applications"; else echo "$HOME/Applications"; fi
}

# curl options: HTTPS only, except http://localhost / 127.0.0.1 for testing
# a local release directory.
fetch() {
  local url="$1" out="$2"
  local proto="=https"
  case "$url" in http://localhost[:/]* | http://127.0.0.1[:/]*) proto="=http,https" ;; esac
  curl --fail --location --silent --show-error --proto "$proto" --proto-redir "$proto" --retry 2 \
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

  step "Checking $base_url" >&2
  fetch "$base_url/latest-mac.yml" "$tmp/latest-mac.yml"

  # electron-builder metadata: "files:" entries of "- url:" followed by "sha512:".
  local entry file sha release_version
  entry="$(awk -v want="-mac-$arch.zip" '
    /^[[:space:]]*-[[:space:]]*url:/ { url = $NF; next }
    /^[[:space:]]+sha512:/ && url != "" { if (index(url, want)) { print url, $NF; exit } url = "" }
  ' "$tmp/latest-mac.yml")"
  [ -n "$entry" ] || die "the release has no macOS $arch build"
  file="${entry%% *}"
  sha="${entry##* }"
  release_version="$(awk '/^version:/ { print $2; exit }' "$tmp/latest-mac.yml" | tr -d "'\"")"
  if [ -n "$version" ] && [ "${version#v}" != "$release_version" ]; then
    die "asked for $version but the release metadata is for $release_version"
  fi

  step "Downloading $APP_NAME $release_version ($arch)" >&2
  fetch "$base_url/$file" "$tmp/$file"

  local actual
  actual="$(openssl dgst -sha512 -binary "$tmp/$file" | base64 | tr -d '\n')"
  [ "$actual" = "$sha" ] || die "SHA-512 mismatch for $file: the download is corrupt or was tampered with"
  say "${DIM}    SHA-512 verified${RESET}" >&2
  echo "$tmp/$file"
}

extract() {
  local tmp="$1" package="$2"
  local out="$tmp/extracted"
  mkdir -p "$out"
  case "$package" in
    *.zip)
      ditto -x -k "$package" "$out" || die "could not unzip $package"
      ;;
    *.dmg)
      local mnt="$tmp/mnt"
      mkdir -p "$mnt"
      hdiutil attach -quiet -nobrowse -readonly -mountpoint "$mnt" "$package" || die "could not open $package"
      ditto "$mnt/$APP_NAME.app" "$out/$APP_NAME.app" || die "$APP_NAME.app not found in $package"
      hdiutil detach -quiet "$mnt" || true
      ;;
    *) die "expected a .zip or .dmg: $package" ;;
  esac
  [ -d "$out/$APP_NAME.app" ] || die "$APP_NAME.app not found in $package"
  echo "$out/$APP_NAME.app"
}

verify_app() {
  local app="$1" allow_unsigned="$2"
  local id
  id="$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$app/Contents/Info.plist" 2>/dev/null || true)"
  [ "$id" = "$BUNDLE_ID" ] || die "unexpected bundle id '$id' (expected $BUNDLE_ID)"

  if [ "$allow_unsigned" = 1 ]; then
    say "${RED}warning:${RESET} skipping signature checks (--allow-unsigned). Only do this for your own builds."
    return
  fi

  step "Verifying signature and notarization"
  codesign --verify --deep --strict "$app" 2>/dev/null || die "the app's code signature is invalid"
  spctl --assess --type execute "$app" 2>/dev/null ||
    die "Gatekeeper rejected the app (not signed with a Developer ID or not notarized)"

  # Still the "__…__" placeholder means the release didn't pin a team id.
  case "$EXPECTED_TEAM_ID" in "" | __*__) EXPECTED_TEAM_ID="" ;; esac
  if [ -n "$EXPECTED_TEAM_ID" ]; then
    local team
    team="$(codesign -dv "$app" 2>&1 | awk -F= '/^TeamIdentifier=/ { print $2 }')"
    [ "$team" = "$EXPECTED_TEAM_ID" ] || die "signed by team '$team', expected $EXPECTED_TEAM_ID"
  fi
  say "${DIM}    signed, notarized, bundle id $BUNDLE_ID${RESET}"
}

quit_running() {
  if pgrep -f "/$APP_NAME.app/Contents/MacOS/" >/dev/null 2>&1; then
    step "Quitting the running agent"
    osascript -e "tell application id \"$BUNDLE_ID\" to quit" >/dev/null 2>&1 || true
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
      pgrep -f "/$APP_NAME.app/Contents/MacOS/" >/dev/null 2>&1 || return 0
      sleep 0.5
    done
    pkill -f "/$APP_NAME.app/Contents/MacOS/" 2>/dev/null || true
  fi
}

do_uninstall() {
  local purge="$1" removed=0 dir
  quit_running
  for dir in "/Applications" "$HOME/Applications" ${KUKUX_AGENT_INSTALL_DIR:+"$KUKUX_AGENT_INSTALL_DIR"}; do
    if [ -d "$dir/$APP_NAME.app" ]; then
      # Drop the kukuxsign:// registration along with the app.
      [ -x "$LSREGISTER" ] && "$LSREGISTER" -u "$dir/$APP_NAME.app" >/dev/null 2>&1 || true
      rm -rf "$dir/$APP_NAME.app" || die "could not remove $dir/$APP_NAME.app"
      say "Removed $dir/$APP_NAME.app"
      removed=1
    fi
  done
  [ "$removed" = 1 ] || say "$APP_NAME is not installed."

  if [ "$purge" = 1 ]; then
    rm -rf "$HOME/Library/Application Support/$APP_NAME" \
      "$HOME/Library/Preferences/$BUNDLE_ID.plist" \
      "$HOME/Library/Caches/$BUNDLE_ID" \
      "$HOME/Library/Caches/$BUNDLE_ID.ShipIt" \
      "$HOME/Library/Logs/$APP_NAME"
    say "Removed settings and paired-app list."
  fi
  say ""
  say "If this computer was paired, revoke it in the web app under ${BOLD}My signing devices${RESET}."
  say "Its keys can't be used without the agent, and no other machine can use them."
}

main "$@"
