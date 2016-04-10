#!/bin/bash

set -e

KEYFILE=/tmp/test-keyfile
CIPHERTEXT=/tmp/test-ciphertext
PLAINTEXT=/tmp/test-plaintext

md5sum encutil.php
php encutil.php --genkey $KEYFILE
php encutil.php --encrypt --keyfile $KEYFILE encutil.php $CIPHERTEXT
php encutil.php --decrypt --keyfile $KEYFILE $CIPHERTEXT $PLAINTEXT
md5sum $PLAINTEXT

php encutil.php --encrypt --password encutil.php $CIPHERTEXT
php encutil.php --decrypt --password $CIPHERTEXT $PLAINTEXT
md5sum $PLAINTEXT

echo "Bad keyfile path #1"
! php encutil.php --genkey ./

echo "Bad keyfile path #2"
! php encutil.php --encrypt --keyfile i-do-not-exist encutil.php $CIPHERTEXT

echo "Bad source path (encrypt, password)"
! php encutil.php --encrypt --password i-do-not-exist blah

echo "Bad source path (decrypt, password)"
! php encutil.php --decrypt --password i-do-not-exist blah

echo "Bad source path (encrypt, keyfile)"
! php encutil.php --encrypt --keyfile $KEYFILE i-do-not-exist blah

echo "Bad source path (decrypt, keyfile)"
! php encutil.php --decrypt --keyfile $KEYFILE i-do-not-exist blah

echo "Bad destination path (encrypt, password)"
! php encutil.php --encrypt --password encutil.php ./

echo "Bad destination path (decrypt, password)"
! php encutil.php --decrypt --password encutil.php ./

echo "Bad destination path (encrypt, keyfile)"
! php encutil.php --encrypt --keyfile $KEYFILE encutil.php ./

echo "Bad destination path (decrypt, keyfile)"
! php encutil.php --decrypt --keyfile $KEYFILE encutil.php ./
