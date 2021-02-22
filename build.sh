#!/bin/bash
# depends on libssl and libcrypto
# install using apt: apt install libssl-dev
# install using brew: brew install openssl
# install using pacman: pacman -S openssl
if [ `uname` = Darwin ]; then
   openssl_path="$(brew --cellar openssl)/$(brew list --versions openssl | tr ' ' '\n' | tail -1)"
   gcc -o fwdhttpsd src/*.c "-I${openssl_path}/include" "${openssl_path}/lib/libssl.a" "${openssl_path}/lib/libcrypto.a" -O2
   exit
elif ! [ `uname` = Linux ]; then
   echo "probably unsupported but trying anyway"
fi
gcc -o fwdhttpsd src/*.c -lpthread -lssl -lcrypto -O2
