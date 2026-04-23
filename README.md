# Pseudo-DNA encryption algorithm

## Description

This project intends to be a pseudo-DNA based cryptography solution for encryption/decryption vast amounts of data.

## Prerequisites

The utilitary is based on `openssl` and `pkg-config` for locating the `openssl` libary for compilation.  
Before compiling, run the following commands   
```
sudo apt update
sudo apt install pkg-config libssl-dev
```

## Installation

clone this repository locally  
`cd crypt-dna`  
`make`

## Usage

for encryption:  
`./bin/crypt-dna -i [INPUT_FILE] -o [OUTPUT_FILE] -p [PASSWORD]`

for decryption:  
`./bin/crypt-dna -d -i [ENCRYPTED_FILE] -o [DECRYPTED_FILE] -p [PASSWORD]`

for reading an encrypted file:  
`./bin/crypt-dna -r [ENCRYPTED_FILE]`

## Acknowledgments

Authors would like to thank to Major Eng. Ștefan-Ciprian Arseni for their guidance, insightful feedback, and encouragement throughout this project.  

## Authors
+ Moraru Andra
+ Nistor Darius