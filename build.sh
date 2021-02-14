#!/bin/bash
if [ `uname` = Darwin ]; then
   openssl_path="$(brew --cellar openssl)/$(brew list --versions openssl | tr ' ' '\n' | tail -1)"
   gcc -o fwdhttpsd *.c "-I${openssl_path}/include" "${openssl_path}/lib/libssl.a" "${openssl_path}/lib/libcrypto.a"
   
   exit
elif ! [ `uname` = Linux ]; then
   echo "probably unsupported but trying anyway"
fi
gcc -o fwdhttpsd *.c -lpthread -lssl -lcrypto
