# Generating the private key with Elliptic curve 256 bit
openssl ecparam -genkey -name prime256v1 -out ClientCert.key


# Generating the certification request
openssl req -new -key ClientCert.key -out ClientCert.csr -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=tnim2314-client"

# ClientCA signing the certification request and authentication usage to ClientCert
openssl x509 -req -in ClientCert.csr -CA ClientCA.crt -CAkey ClientCA.key -CAcreateserial -out ClientCert.crt -days 45 -extfile config_client_cert
# - digitalSignature: Can sign data
# - keyEncipherment: can be used for key exchange and encryption
# - clientAuth: mainly to be used for client authentication


# how to view the certification details
openssl x509 -in ClientCert\ClientCert.crt -text -noout