openssl ecparam -name secp128r1 -genkey -out rafaECkey.pem

openssl ecparam -name secp128r1 -genkey -out lachicaECkey.pem

#obtenemos la clave privada

openssl aes-128-cbc -in rafaECkey.pem -out rafaECpriv.pem

openssl aes-128-cbc -in lachicaECkey.pem -out lachicaECpriv.pem

#obtenemos la clave publica
openssl ec -in rafaECkey.pem -pubout -text -out rafaECpub.pem

openssl ec -in lachicaECkey.pem -pubout -text -out lachicaECpub.pem


