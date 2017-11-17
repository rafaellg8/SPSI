openssl pkeyutl -inkey rafaECpriv.pem -peerkey lachicaECpub.pem -derive -out key.bin

#hacemos lo mismo con la otra clave
openssl pkeyutl -inkey lachicaECpriv.pem -peerkey rafaECpub.pem -derive -out key2.bin

