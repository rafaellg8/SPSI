#Ejercicio 6
#AES 128
#ECB
openssl enc -aes-128-ecb -in input.bin -out cipherAES128ECB-Input.txt -K 1010

openssl enc -aes-128-ecb -in input1.bin -out cipherAES128ECB-Input1.txt -K 1010


#CBC
openssl enc -aes-128-cbc -in input.bin -out cipherAES128CBC-Input.txt -K 1010 -iv 0


openssl enc -aes-128-cbc -in input1.bin -out cipherAES128CBC-Input1.txt -K 1010 -iv 0


#AES 256
#ECB
openssl enc -aes-256-ecb -in input.bin -out cipherAES256ECB-Input.txt -K 1010

openssl enc -aes-256-ecb -in input1.bin -out cipherAES256ECB-Input1.txt -K 1010


#CBC

openssl enc -aes-256-cbc -in input.bin -out cipherAES256CBC-Input.txt -K 1010 -iv 0

openssl enc -aes-256-cbc -in input1.bin -out cipherAES256CBC-Input1.txt -K 1010 -iv 0


