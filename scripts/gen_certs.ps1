$OPENSSL = "C:\Program Files (x86)\EasyPHP-Devserver-17\eds-binaries\httpserver\apache2425vc11x86x231101114403\bin\openssl.exe"
$CERTS_DIR = "c:\Users\Dalell\banking-api-secure\nginx_certs"
$CONFIG_FILE = "c:\Users\Dalell\banking-api-secure\scripts\openssl.cnf"

# Créer un fichier de configuration minimal pour OpenSSL
@'
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = Banking-API-CA

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical,CA:true
'@ | Out-File -FilePath $CONFIG_FILE -Encoding ascii

Write-Host "--- Génération de la CA ---"
& $OPENSSL genrsa -out "$CERTS_DIR\ca.key" 4096
& $OPENSSL req -new -x509 -days 3650 -key "$CERTS_DIR\ca.key" -out "$CERTS_DIR\ca.crt" -config $CONFIG_FILE

# Mettre à jour le config pour le client
@'
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = Trusted-TPP-Client
'@ | Out-File -FilePath $CONFIG_FILE -Encoding ascii

Write-Host "--- Génération du Certificat Client ---"
& $OPENSSL genrsa -out "$CERTS_DIR\client.key" 2048
& $OPENSSL req -new -key "$CERTS_DIR\client.key" -out "$CERTS_DIR\client.csr" -config $CONFIG_FILE

Write-Host "--- Signature du Certificat Client ---"
& $OPENSSL x509 -req -days 365 -in "$CERTS_DIR\client.csr" -CA "$CERTS_DIR\ca.crt" -CAkey "$CERTS_DIR\ca.key" -set_serial 01 -out "$CERTS_DIR\client.crt"

Write-Host "✅ Certificats mTLS générés dans $CERTS_DIR"
