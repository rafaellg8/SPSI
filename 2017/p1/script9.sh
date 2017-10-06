#Volvemos a cifrar el Output.bin otra vez y guardamos el resultado en output2.bin

openssl enc -aes-192-ofb -in output.bin -out output2.bin -K 1010 -iv 0
