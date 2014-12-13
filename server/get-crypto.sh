#!/bin/bash

PKG="pycrypto-2.6.1"
rm -rf $PKG*

curl -LO https://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.1.tar.gz
tar -xzvf $PKG.tar.gz
cd $PKG
python2.7 setup.py build
cp -r build/lib*/Crypto ..
