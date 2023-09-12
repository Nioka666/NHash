#NHash - Secure Text Encryption and Decryption Tool

NHash is a Python-based command-line tool that provides secure text encryption and decryption using various encryption methods. It supports multiple encryption techniques, including Fernet, PBKDF2, RSA, and AES. This tool is designed to help users protect their sensitive text data with strong encryption algorithms.

## Features

- **Multiple Encryption Methods**: NHash offers a choice of encryption methods, allowing you to select the most suitable one for your needs.

- **Strong Encryption**: All encryption methods provided by NHash use strong cryptographic algorithms to ensure the security of your data.

- **Easy-to-Use Command Line Interface**: NHash provides a simple and intuitive command-line interface (CLI) that makes it easy for users to encrypt and decrypt text.

## Table of Contents

- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Installation Steps](#installation-steps)
- [Usage](#usage)
  - [Encrypting Text](#encrypting-text)
    - [Fernet Encryption](#fernet-encryption)
    - [PBKDF2 Encryption](#pbkdf2-encryption)
    - [RSA Encryption](#rsa-encryption)
    - [AES Encryption](#aes-encryption)
  - [Decrypting Text](#decrypting-text)
    - [Fernet Decryption](#fernet-decryption)
    - [PBKDF2 Decryption](#pbkdf2-decryption)
    - [RSA Decryption](#rsa-decryption)
    - [AES Decryption](#aes-decryption)
- [Contributing](#contributing)
- [License](#license)

## Installation

## Pre-Requisites

Before you can use NHash, ensure you have the following prerequisites installed:

- Python (version 3.6 or higher)
- pip (Python package manager)

## Installation Steps

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/yourusername/NHash.git

2. Navigate to the project directory:
    ```bash
    cd NHash

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt

4. Run NHash !
    ```bash
    python3 NHash.py

## Usages

NHash provides two main commands: encrypt and decrypt. You can choose from different encryption methods and provide the required input and options as needed.

## Encrypting

1. Farnet Encryption
    ```bash
    python3 NHash.py encrypt -m fernet -t "Your sensitive text" -o encrypted.txt

2. AES Encryption
    ```bash
    python3 NHash.py decrypt -m aes -i encrypted.txt -k aes_key.key -iv iv_aes.key

## Decrypting

1. Farnet Decryption
    ```bash
    python3 NHash.py decrypt -m fernet -i encrypted.txt

2. AES Decryption
    ```bash
    python NHash.py decrypt -m aes -i encrypted.txt -k aes_key.key -iv iv_aes.key

## Contributing

If you'd like to contribute to NHash or report issues, please check our contribution guidelines. and Thanks ..


