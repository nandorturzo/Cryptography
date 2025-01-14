# Generating the private key with Elliptic curve 256 bit
openssl ecparam -genkey -name prime256v1 -out ServerCA.key

# Generating the certification request
openssl req -new -key ServerCA.key -out ServerCA.csr -subj "/C=RO/ST=Kolozs/L=Kolozsvar/O=BBTE/CN=tnim2314-ServerCA"

# RootCA signing the certification request and adding CA permissions to ServerCA
openssl x509 -req -in ServerCA.csr -CA RootCA.crt -CAkey RootCA.key -CAcreateserial -out ServerCA.crt -days 45 -extfile config_ca.cnf
# - digitalSignature: Can sign data
# - keyCertSign: Can sign other certificates
# - cRLSign: Can sign CRLs (Certificate Revocation Lists)


# how to view the certification details
openssl x509 -in ServerCA\ServerCA.crt -text -noout