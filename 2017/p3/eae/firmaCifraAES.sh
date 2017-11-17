openssl enc -aes-128-cfb8 -in publicas.sig -pass file:key.bin -out firmadaCIFRADA.sig
openssl enc -aes-128-cfb8 -in publicas2.sig -pass file:key2.bin -out firmada2CIFRADA2.sig
