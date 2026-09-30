#!/bin/sh
# Compiles SecureEnclaveBlob.swift into an object for the addon (binding.gyp).
#   swiftc.sh <node-gyp target_arch: arm64|x64> <input.swift> <output.o>
set -eu
case "$1" in
  arm64) triple=arm64-apple-macos12.0 ;;
  x64) triple=x86_64-apple-macos12.0 ;;
  *) echo "swiftc.sh: unsupported arch $1" >&2; exit 1 ;;
esac
mkdir -p "$(dirname "$3")"
exec xcrun swiftc -parse-as-library -O -whole-module-optimization -module-name KukuxSE \
  -target "$triple" -emit-object "$2" -o "$3"
