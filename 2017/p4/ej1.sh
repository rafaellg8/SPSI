mkdir certs
mkdir private
mkdir newcerts
mkdir crl
echo "01" > serial
touch index.txt

#Ejercicio1 Generar certificado
openssl req -nodes -new -x509 -keyout private/cakey.pem -out cacert.pem -days 365
