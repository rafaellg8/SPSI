#11.3

#Clave débiles

#ECB
openssl enc -rc2-ecb -in input.bin -out rc2-ECB.txt -K 0101010101010101

#CBC
Openssl enc -rc2-cbc -in input.bin -out rc2-CBC.txt -K 0101010101010101 -iv 0

#OFB

openssl enc -rc2-ofb -in input.bin -out rc2-OFB.txt -K 0101010101010101 -iv 0
#--------------------

#Claves semidébiles
#ECB
openssl enc -rc2-ecb -in input.bin -out rc2-ECBv2.txt -K 01FE01FE01FE01FE

#CBC
Openssl enc -rc2-cbc -in input.bin -out rc2-CBCv2.txt -K 01FE01FE01FE01FE -iv 0

#OFB

openssl enc -rc2-ofb -in input.bin -out rc2-OFBv2.txt -K 01FE01FE01FE01FE -iv 0

#--------------------


#11.4

openssl enc -rc2-ecb -in input.bin -out rc2-ECB-input.txt -K ABCD

openssl enc -rc2-ecb -in input1.bin -out rc2-ECB-input1.txt -K ABCD

#--------------------


#11.5
openssl enc -rc2-ecb -in input.bin -out rc2-CBC-input.txt -K ABCD -iv 0

openssl enc -rc2-ecb -in input1.bin -out rc2-CBC-input1.txt -K ABCD -iv 0


