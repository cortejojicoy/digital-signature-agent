// The Philippine PKI root the certificate preview recognises
// (pkcs12-key-storage-plan.md §6.2). Public data. Only for the preview's
// "issued under the Philippine PKI" note: the app's server decides whether
// it trusts a certificate.
//
// Taken from the chain inside DICT's UP test certificates and pinned by its
// SHA-256 fingerprint. Confirm the fingerprint against DICT's published root
// (rootca.npki.gov.ph) when it changes.
export const PNPKI_ROOTS: ReadonlyArray<{ name: string; fingerprint256: string; pem: string }> = [
  {
    name: 'Philippine Root CA - G2',
    fingerprint256: 'DE:CD:32:E1:F8:BF:DC:F8:54:3E:E1:A9:A6:0F:1F:94:62:F5:C3:46:F9:99:33:4E:E4:74:FE:53:A3:E0:F6:B9',
    pem: `-----BEGIN CERTIFICATE-----
MIIFuTCCA6GgAwIBAgIUH3X6j+CCMy0nfvNNYWTw6Yvi2g8wDQYJKoZIhvcNAQEN
BQAwPjEgMB4GA1UEAwwXUGhpbGlwcGluZSBSb290IENBIC0gRzIxDTALBgNVBAoM
BERJQ1QxCzAJBgNVBAYTAlBIMB4XDTIzMTIxMTA4MDcwMloXDTQ4MTIwNDA4MDcw
MVowPjEgMB4GA1UEAwwXUGhpbGlwcGluZSBSb290IENBIC0gRzIxDTALBgNVBAoM
BERJQ1QxCzAJBgNVBAYTAlBIMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEAoRUpgeMeOk2L9zJ0axGHfoEyUeMLgoGOTie+hbusIR6Lyu3IuabfK9Ho7M6m
zeg+tQjeXQB3HCvPqIEmI09KC0taPR8WChbc7GhgUa3oczP3j6oPwyaGXB6GYkb0
jjVVgljw7wJlA7gL+oasits33Pfc7F54HHsgSDqClYk61m85D1hWdujvkgA0P7fw
1YNzQzF9IYeV+121I/DilpTvnyr15LCLRtQ1BJQ2tycy60CtnfejtHYGc46yAE3i
q3L5vToz/5CLruAPfUH838VSliDSJPVCFdc1fFWTOsYOsTCNsrydXwJIy5yGmYuz
G3/BjS11unhLvzblpvzLjSoTRWTpJGOFwBpaCWCRVxvkbLFJxBLVHT26skTQtmXH
cIe1yeQEzWMuPRGnOiN7dk0wJJ2julhe9q82+gmf/oL8seaTQtsF+QA4eA4VdQu4
2YdVrXu6fDuphptJu+vFt9zNEIHjoOAlRz8OSVh9LOu6Ofs8BL7u/zWE+SJQLe0X
nf3wC2ZCNQTZgXNR7Tbsh61rvRur8Gf+LMCiNmYYR3/sKQ3fzUeGJi/ARM6lAHAY
ycd1tRVsMzpir1ajtmfpJKZdnmydMpbXQbPEUcDjBpUXmY37hJh+4miwwrVdRUVn
jHs2CWqtGGvdSPQw13nWsOZI1yOTCFb+/UFeGIX3/difDvUCAwEAAaOBrjCBqzAP
BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFBSKoXYG5iClLAJGwMsmdQ+6rhgo
MEgGA1UdIARBMD8wPQYEVR0gADA1MDMGCCsGAQUFBwIBFidodHRwOi8vcm9vdGNh
Lm5wa2kuZ292LnBoL2NwL1Jvb3RDQS5odG0wHQYDVR0OBBYEFBSKoXYG5iClLAJG
wMsmdQ+6rhgoMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQ0FAAOCAgEABhjG
2V6ihBF/9Pcm3zq401jyO9tHBb/wwWiJ+q8vmjwt630b21VUEs6ZtzJCN8Jfte/x
spnme8z+b3IydCydJN1nlaY24yZd4DECcVpsccNDj21px5+dtvjF7d5XOvhdudM3
LcWv8ndSMcrAcecX6xFdGXFeMfSPlELfHKIYNYAbhsOpxLVifvKzM0Gde11SjihT
WTf0tV92ker09+aGEjYnw6du7j0W8LmKkC1+HkYspLxcPKJR7MnFl7s7IGNbtiRv
dz6CCW6WilEhUtX9BpYbGzplJeXyDv6V1LIdBhFgdGFaZ2PZpbkRPgWNy8+JT5ch
x9CzUQ9mX9NiaSKj2X+sFXdfcAWFO9LDcMLrJwafjha6ww1unos8DqVvQmxzN7te
Du0HX/xY1eO+qw2CnMV9KgFhWw9AECFHH92/6VNMZ0CnWcVd0ckv6h9mPIXUmQ5k
JRNHCyKRjGANBkFNEtdrzuyRFBYuRtYnOvD9r7nVMCD2KNaqHcKKk8ZzsTAuqzdT
0oYeHahn1aiudzlpOiuQVnK3+X2Eg1qioLQHAuvKBt8qzL+OZ03VYq79S9fZbVzp
fzyG6QWRG/zHadZyHLHiuNI3UqnkijWKulHJ8w+DioC8CRCyFXd6OFlVut2fYJs3
mo213uXI9+cjJOjOU9O+5FN+wkNfj2jjIPrt3Ls=
-----END CERTIFICATE-----`,
  },
];
