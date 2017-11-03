openssl rsautl -decrypt -inkey rafaPRIV.pem -in sessionkey.bin -out sessionkey2.txt
openssl enc -d -aes-128-cbc -in mensajeHibrido.bin -out mensajeHibrido.txt -pass file:sessionkey2.txt
