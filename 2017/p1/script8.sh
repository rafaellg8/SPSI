#Desencriptacion 
#Usamos el parametro -d (decrypt) para el desencriptado del archvio anterior que encriptamos en output.bin
openssl aes-192-ofb -d -in output.bin -out descifrado8.txt -K 1010 -iv 0

