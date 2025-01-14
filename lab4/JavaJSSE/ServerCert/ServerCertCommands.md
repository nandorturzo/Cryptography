# Generating the private key with RSA 2048 bit
openssl genrsa -out ServerCert.key 2048

# Generating the certification request
openssl req -new -key ServerCert.key -out ServerCert.csr -subj "/C=RO/ST=Kolozs/L=Kolozsvr/O=BBTE/CN=$(hostname)"

# ServerCA signing the certification request and authentication usage to ServerCert
openssl x509 -req -in ServerCert.csr -CA ServerCA.crt -CAkey ServerCA.key -CAcreateserial -out ServerCert.crt -days 45 -extfile config_server_cert.cnf
# - digitalSignature: Can sign data
# - keyEncipherment: can be used for key exchange and encryption
# - serverAuth: mainly to be used for server authentication


# how to view the certification details
openssl x509 -in ServerCert\ServerCert.crt -text -noout