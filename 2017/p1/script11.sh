#11.3
openssl enc -rc4 -in input.bin -out rc4.txt -K 0101010101010101
openssl enc -rc4 -in input.bin -out rc4-v2.txt -K 01FE01FE01FE01FE

#11.4

openssl enc -rc4 -in input1.bin -out rc4-input1.txt -K 01FEAA
openssl enc -rc4 -in input1.bin -out rc4-input1-v2.txt -K 01FEAA


#11.5
#no tiene vector de inicializacion

