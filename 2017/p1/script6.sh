#Ejercicio 6
#AES 128
#ECB
openssl enc -aes-128-ecb -in input1.bin -out cipherAES128ECB.txt -K 1010

#CBC
openssl enc -aes-128-cbc -in input1.bin -out cipherAES128CBC.txt -K 1010 -iv 0


#AES 256
#ECB
openssl enc -aes-256-ecb -in input1.bin -out cipherAES256ECB.txt -K 1010

#CBC
openssl enc -aes-256-cbc -in input1.bin -out cipherAES256CBC.txt -K 1010 -iv 0

