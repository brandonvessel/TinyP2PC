/*
This file is part of TinyP2PC

Github: https://github.com/brandonvessel/TinyP2PC

THIS LICENSE MUST REMAIN AT THE TOP OF THIS FILE

TinyP2PC is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

TinyP2PC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TinyP2PC.  If not, see <https://www.gnu.org/licenses/>.
*/
#pragma once

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>


int public_encrypt( unsigned char * data,     int data_len, unsigned char * key, unsigned char * encrypted);
int public_decrypt( unsigned char * enc_data, int data_len, unsigned char * key, unsigned char * decrypted);

int private_encrypt(unsigned char * data,     int data_len, unsigned char * key, unsigned char * encrypted);
int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char * decrypted);


RSA * createRSA(unsigned char * key, int public);
