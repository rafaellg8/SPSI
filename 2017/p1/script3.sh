#ECB
openssl enc -des-ecb -in input.bin -out cipherECB.txt -K 0101010101010101

#CBC
openssl enc -des-cbc -in input.bin -out cipherCBC.txt -K 0101010101010101 -iv 0

#OFB
openssl enc -des-ofb -in input.bin -out cipherOFB.txt -K 0101010101010101 -iv 0


##Claves semidébiles

openssl enc -des-ecb -in input.bin -out cipherECB2.txt -K 01FE01FE01FE01FE

openssl enc -des-cbc -in input.bin -out cipherCBC2.txt -K 01FE01FE01FE01FE -iv 0

openssl enc -des-ofb -in input.bin -out cipherOFB2.txt -K 01FE01FE01FE01FE -iv 0


