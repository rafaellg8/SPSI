#ECB
openssl enc -des-ecb -in input1.bin -out cipherECB.txt -K 0101010101010101

#CBC
openssl enc -des-cbc -in input1.bin -out cipherCBC.txt -K 0101010101010101 -iv 0

#OFB
openssl enc -des-ofb -in input1.bin -out cipherOFB.txt -K 0101010101010101 -iv 0

