# Generating the private key with Elliptic curve 256 bit
openssl ecparam -genkey -name prime256v1 -out RootCA.key

# Generating the certification request
openssl req -new -key RootCA.key -out RootCA.csr -subj "/C=RO/ST=Kolozs/L=Kolozsvár/O=BBTE/CN=tnim2314-RootCA"

# Self-signing the certification request and adding CA permissions
openssl x509 -req -in RootCA.csr -signkey RootCA.key -out RootCA.crt -days 45 -extfile config_ca.cnf
# - digitalSignature: Can sign data
# - keyCertSign: Can sign other certificates 
# - cRLSign: Can sign CRLs (Certificate Revocation Lists)


# how to view the certification details
openssl x509 -in RootCA\RootCA.crt -text -noout
