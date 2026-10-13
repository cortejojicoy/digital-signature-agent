#!/bin/sh
# Builds the throwaway PKCS#12 fixtures in test/fixtures/pkcs12/
# (pkcs12-key-storage-plan.md §11.1). Run once; the output is committed.
#
# Every file's password is "test". The CA is made up here and trusted by
# nothing, so these files are worthless outside the tests. Never put a real
# certificate (e.g. a PNPKI .p12) in the repo: .gitignore excludes *.p12
# everywhere except that folder.
#
# Needs OpenSSL 3.4+ (for -not_before / -not_after).
set -eu

out="$(cd "$(dirname "$0")/.." && pwd)/test/fixtures/pkcs12"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
cd "$work"

pass=pass:test

cat > leaf.ext <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
EOF
cat > encipher.ext <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, keyEncipherment
EOF
cat > ca.ext <<'EOF'
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

# Root → intermediate → leaves, like the PNPKI chain but shorter.
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 7300 \
  -subj "/CN=Kukux Test Root CA/O=Kukux Test/C=PH" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout inter.key -out inter.csr \
  -subj "/CN=Kukux Test Signing CA/O=Kukux Test/C=PH" 2>/dev/null
openssl x509 -req -in inter.csr -CA root.crt -CAkey root.key -CAcreateserial -days 7300 \
  -extfile ca.ext -out inter.crt 2>/dev/null
cat inter.crt root.crt > chain.pem

# KEYALG=<openssl -newkey arg> leaf <name> <ext file> <x509 date args…>
leaf() {
  name=$1; ext=$2; shift 2
  openssl req -newkey "$KEYALG" -nodes -keyout "$name.key" -out "$name.csr" \
    -subj "/CN=Test Signer $name/serialNumber=000000000/O=Kukux Test/C=PH" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA inter.crt -CAkey inter.key -CAcreateserial \
    -extfile "$ext" -out "$name.crt" "$@" 2>/dev/null
}

KEYALG=rsa:2048 leaf rsa leaf.ext -days 3650
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out p256.key 2>/dev/null
openssl req -new -key p256.key -out p256.csr -subj "/CN=Test Signer p256/O=Kukux Test/C=PH" 2>/dev/null
openssl x509 -req -in p256.csr -CA inter.crt -CAkey inter.key -CAcreateserial -extfile leaf.ext \
  -days 3650 -out p256.crt 2>/dev/null
KEYALG=rsa:1024 leaf rsa1024 leaf.ext -days 3650
KEYALG=rsa:2048 leaf encipher encipher.ext -days 3650
KEYALG=rsa:2048 leaf expired leaf.ext -not_before 20200101000000Z -not_after 20210101000000Z

legacy="-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1"
modern="-certpbe AES-256-CBC -keypbe AES-256-CBC -macalg sha256"

# 3DES + SHA-1 MAC, the format of the real PNPKI test files.
openssl pkcs12 -export $legacy -inkey rsa.key -in rsa.crt -certfile chain.pem \
  -name "Test Signer rsa" -passout $pass -out "$out/rsa2048-legacy.p12"
openssl pkcs12 -export $modern -inkey rsa.key -in rsa.crt -certfile chain.pem \
  -name "Test Signer rsa" -passout $pass -out "$out/rsa2048-aes.p12"
openssl pkcs12 -export $modern -inkey p256.key -in p256.crt -certfile chain.pem \
  -passout $pass -out "$out/p256.p12"
openssl pkcs12 -export $modern -inkey rsa1024.key -in rsa1024.crt -certfile chain.pem \
  -passout $pass -out "$out/rsa1024.p12"
openssl pkcs12 -export $modern -inkey encipher.key -in encipher.crt -certfile chain.pem \
  -passout $pass -out "$out/no-nonrepudiation.p12"
openssl pkcs12 -export $modern -inkey expired.key -in expired.crt -certfile chain.pem \
  -passout $pass -out "$out/expired.p12"
# Certificates only, no private key.
openssl pkcs12 -export $modern -nokeys -in rsa.crt -certfile chain.pem \
  -passout $pass -out "$out/ca-only.p12"

# The parts of rsa2048-*.p12 separately, for tests whose key store can't
# parse PKCS#12 (test/support/memory-keystore.ts) and for the mock server's
# trusted root. The key is as throwaway as the rest.
openssl x509 -in rsa.crt -outform DER -out "$out/rsa2048-leaf.cer"
openssl pkcs8 -topk8 -nocrypt -in rsa.key -out "$out/rsa2048-leaf.key"
openssl x509 -in inter.crt -outform DER -out "$out/test-intermediate.cer"
openssl x509 -in root.crt -outform DER -out "$out/test-root.cer"
openssl x509 -in expired.crt -outform DER -out "$out/expired-leaf.cer"
openssl x509 -in encipher.crt -outform DER -out "$out/no-nonrepudiation-leaf.cer"
# Another leaf under the same CA, for replacing a certificate.
KEYALG=rsa:2048 leaf second leaf.ext -days 3650
openssl pkcs12 -export $modern -inkey second.key -in second.crt -certfile chain.pem \
  -passout $pass -out "$out/second.p12"
openssl x509 -in second.crt -outform DER -out "$out/second-leaf.cer"
openssl pkcs8 -topk8 -nocrypt -in second.key -out "$out/second-leaf.key"

echo "wrote $(ls "$out" | wc -l | tr -d ' ') files to $out"
