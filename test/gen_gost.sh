# GOST fixtures: gen_gost.sh <dir>, with <dir>/raw the 32-byte little-endian
# private scalar. Writes <dir>/eng.cnf, an openssl config on the engine named
# by MINIPKI_GOST_ENGINE (the CLI GOST provider cannot verify X.509
# signatures), and the self-signed certificate ca.der and its CRL crl.der.
set -e
D="$1"; cd "$D"
printf 'openssl_conf=i\n[i]\nengines=e\n[e]\ngost=g\n[g]\ndynamic_path=%s\ndefault_algorithms=ALL\n' \
    "$MINIPKI_GOST_ENGINE" > eng.cnf
export OPENSSL_CONF=eng.cnf
{ printf '\060\106\002\001\000\060\037\006\010\052\205\003\007\001\001\001\001'
  printf '\060\023\006\007\052\205\003\002\002\043\001\006\010\052\205\003\007\001\001\002\002\004\040'
  cat raw; } > key.der
openssl pkey -inform DER -in key.der -out key.pem
mkdir -p db; : > db/index.txt; echo 01 > db/crlnumber
openssl req -x509 -key key.pem -md_gost12_256 -subj /CN=GOST -days 30 -out ca.pem \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
printf '[ca]\ndefault_ca=c\n[c]\ndatabase=db/index.txt\ncrlnumber=db/crlnumber\ncertificate=ca.pem\nprivate_key=key.pem\ndefault_md=md_gost12_256\ndefault_crl_days=30\n' > ca.cnf
openssl ca -config ca.cnf -gencrl -out crl.pem
openssl x509 -in ca.pem -outform DER -out ca.der
openssl crl -in crl.pem -outform DER -out crl.der
