openssl enc -d -aes-128-cfb8 -in firmada2CIFRADA2.sig -pass file:key.bin -out firmaDescifrada.sig
openssl dgst -c -verify lachicaDSApub.pem -signature firmaDescifrada.sig publicas2.pem

#hacemos lo mismo para el otro usuario, desciframos y verificamos

openssl enc -d -aes-128-cfb8 -in firmadaCIFRADA.sig -pass file:key2.bin -out descifradoFirmado2.sig
openssl dgst -c -verify rafaDSApub.pem -signature descifradoFirmado2.sig publicas.pem
