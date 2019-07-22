# zcrypto

openssl genrsa -out privatekey.pem 1024
openssl req -new -key privatekey.pem -out certrequest.csr
openssl x509 -req -in certrequest.csr -signkey privatekey.pem -out certificate.pem

openssl pkcs12 -export -out Cert.p12 -in certificate.pem -inkey privatekey.pem -passin pass:root -passout pass:root


