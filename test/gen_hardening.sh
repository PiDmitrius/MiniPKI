# Fixtures for the hardening tests: gen_hardening.sh <dir>
set -e
D="$1"; mkdir -p "$D"; cd "$D"
k() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" 2>/dev/null; }
k root; k inter; k leaf; k evil; k eleaf
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ca.ext
printf 'basicConstraints=critical,CA:FALSE\n' > ee.ext
openssl req -x509 -key root.key -subj /CN=Root -days 30 -out root.pem -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
openssl req -new -key inter.key -subj /CN=Inter | openssl x509 -req -CA root.pem -CAkey root.key -set_serial 2 -days 30 -extfile ca.ext -out inter.pem 2>/dev/null
openssl req -new -key leaf.key -subj /CN=Leaf | openssl x509 -req -CA inter.pem -CAkey inter.key -set_serial 3 -days 30 -extfile ee.ext -out leaf.pem 2>/dev/null
openssl req -x509 -key evil.key -subj /CN=Evil -days 30 -out evil.pem -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
openssl req -new -key eleaf.key -subj /CN=EvilLeaf | openssl x509 -req -CA evil.pem -CAkey evil.key -set_serial 4 -days 30 -extfile ee.ext -out eleaf.pem 2>/dev/null
oid="1.3.6.1.4.1$(i=0; while [ $i -lt 40 ]; do printf '.123456'; i=$((i+1)); done)"
openssl req -x509 -key leaf.key -subj /CN=LongEKU -days 30 -out longeku.pem -addext "extendedKeyUsage=$oid" 2>/dev/null
for f in root inter leaf evil eleaf longeku; do openssl x509 -in $f.pem -outform DER -out $f.der; done
end=$(openssl x509 -in leaf.pem -noout -enddate | cut -d= -f2)
printf 'V\t%s\t\t03\tunknown\t/CN=Leaf\n' "$(date -u -d "$end" +%y%m%d%H%M%SZ)" > index.txt
openssl ocsp -issuer inter.pem -sha256 -cert leaf.pem -no_nonce -reqout req.der 2>/dev/null
openssl ocsp -index index.txt -rsigner inter.pem -rkey inter.key -CA inter.pem -reqin req.der -respout ocsp256.der 2>/dev/null
openssl crl2pkcs7 -nocrl -certfile leaf.pem -outform DER -out p7.der
{ cat leaf.der; printf '\n'; cat evil.pem; } > derpem.bin
{ cat p7.der; printf 'X'; } > p7junk.bin
