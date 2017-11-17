openssl ecparam -name secp128r1 -genkey -out rafaECkey.pem

openssl ecparam -name secp128r1 -genkey -out lachicaECkey.pem

#obtenemos la clave privada

openssl ec -in rafaECkey.pem -des3 -out rafaECpriv.pem


openssl ec -in lachicaECkey.pem -des3 -out lachicaECpriv.pem

#obtenemos la clave publica
openssl ec -in rafaECkey.pem -pubout -text -out rafaECpub.pem

openssl ec -in lachicaECkey.pem -pubout -text -out lachicaECpub.pem
