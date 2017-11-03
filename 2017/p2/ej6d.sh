openssl enc -aes-128-cbc -in mensaje.txt -pass file:sessionkey.txt -out mensajeHibrido.bin
