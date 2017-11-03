#Generamos encriptacion
openssl genrsa 768 -out rafaRSAKey.pem

#obtenemos la clave privada
openssl rsa -in rafaRSAKey.pem -aes-128-cbc -out rafaPRIV.pem

#obtenemos la clave publica
openssl rsa -in rafaRSAKey.pem -pubout -out rafaRSApub.pem
