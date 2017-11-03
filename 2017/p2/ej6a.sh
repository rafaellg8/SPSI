openssl rand -hex 32 -out sessionkey.txt

echo -aes-128-cbc >> sessionkey.txt
