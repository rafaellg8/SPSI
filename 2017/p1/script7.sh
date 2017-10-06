#Cifrad input.bin con AES-192 en modo OFB , clave
#y vector de inicializacion a elegir. Supongamos que
#la salida es output.bin
openssl enc -aes-192-ofb -in input.bin -out output.bin -K 1010 -iv 0
