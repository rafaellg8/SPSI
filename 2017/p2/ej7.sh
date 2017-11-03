#generar clave aleatoria
openssl rand -hex 32 -out randomkey.txt
echo -aes-128-cbc >> randomkey.txt

#Cifrar clave, con la clave publica
openssl rsautl -encrypt -inkey rafaRSApub.pem -pubin -in randomkey.txt -out randomkey.enc

#Finalmente ciframos el mensaje
openssl enc -aes-128-cbc -in input.bin -out output.bin -pass file:randomkey.txt


#Desencriptamos la llave
openssl rsautl -decrypt -inkey rafaPRIV.pem -in randomkey.enc -out randomkey2.txt

#Y ya podemos desencriptar el mensaje
openssl enc -d -aes-128-cbc -in output.bin -out output2.bin -pass file:randomkey2.txt
