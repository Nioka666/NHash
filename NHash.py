# NHash, Encrypting tools
# 
# Nioka666 - @nioka.o
# 

import click
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

@click.group()
def cli():
    pass

def generate_aes_key_iv():
    key = os.urandom(32)  # Kunci AES dengan panjang 256 bit (32 byte)
    iv = os.urandom(16)   # Initialization Vector (IV) dengan panjang 128 bit (16 byte)
    return key, iv

@cli.command()
@click.option('-m', '--method', type=click.Choice(['fernet', 'pbkdf2', 'rsa', 'aes']), prompt='Choose encryption method', help='The encryption method to be used')
@click.option('-t', '--text', prompt='Enter the text to be encrypted', help='The text to be encrypted')
@click.option('-o', '--output', prompt='Output file name', default='encrypted.txt', help='The name of the output file')
@click.option('-k', '--key-file', help='Key file name (only for RSA and AES methods)')
@click.option('-iv', '--initialization-vector', help='Initialization Vector (IV) for AES (only for the AES method)')

def encrypt(method, text, output, key_file, initialization_vector):
    if method == 'fernet':
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_text = cipher_suite.encrypt(text.encode())
        with open(output, 'wb') as file:
            file.write(encrypted_text)
        click.echo(f'The text has been encrypted using the Fernet method and stored in a file {output}')
        with open('key.key', 'wb') as key_file:
            key_file.write(key)

    elif method == 'pbkdf2':
        salt = os.urandom(16)
        key = base64.urlsafe_b64encode(os.urandom(32))
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(key))
        cipher = Fernet(key)
        encrypted_text = cipher.encrypt(text.encode())
        with open(output, 'wb') as file:
            file.write(encrypted_text)
        click.echo(f'The text has been encrypted using the PBKDF2 method and stored in a file {output}')
        with open('key.key', 'wb') as key_file:
            key_file.write(key)

    elif method == 'rsa':
        if key_file is None:
            click.echo("The RSA key file name is required for the RSA method.")
            return
        try:
            with open(key_file, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            encrypted_text = private_key.encrypt(
                text.encode(),
                padding.PKCS1v15()
            )
            with open(output, 'wb') as file:
                file.write(encrypted_text)
            click.echo(f'The text has been encrypted using the RSA method and stored in a file {output}')
        except Exception as e:
            click.echo(f'Failed to encrypt with RSA: {str(e)}')

    elif method == 'aes':
        key, iv = generate_aes_key_iv()
        try:
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padded_data = text.encode() + b"\0" * (16 - len(text) % 16)  # PKCS7 padding
            encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
            with open(output, 'wb') as file:
                file.write(encrypted_text)
            click.echo(f'The text has been encrypted using the AES method and saved in a file {output}')
            with open('key_aes.key', 'wb') as key_file:
                key_file.write(key)
            with open('iv_aes.key', 'wb') as iv_file:
                iv_file.write(iv)
        except Exception as e:
            click.echo(f'Failed to perform encryption with AES: {str(e)}')

@cli.command()
@click.option('-m', '--method', type=click.Choice(['fernet', 'pbkdf2', 'rsa', 'aes']), prompt='Choose decryption method', help='The decryption method to be used')
@click.option('-i', '--input', type=click.File('rb'), prompt='Input file', help='The file to be decrypted')
@click.option('-k', '--key-file', help='Key file name (only for RSA and AES methods)')
@click.option('-iv', '--initialization-vector', help='Initialization Vector (IV) for AES (only for the AES method)')

def decrypt(method, input, key_file, initialization_vector):
    encrypted_text = input.read()

    if method == 'fernet':
        with open('key.key', 'rb') as key_file:
            key = key_file.read()
        cipher_suite = Fernet(key)
        decrypted_text = cipher_suite.decrypt(encrypted_text)
        click.echo(f'Decrypted text: {decrypted_text.decode()}')

    elif method == 'pbkdf2':
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=salt,
            iterations=100000,
        )
        with open('key.key', 'rb') as key_file:
            key = key_file.read()
        key = base64.urlsafe_b64encode(kdf.derive(key))
        cipher = Fernet(key)
        decrypted_text = cipher.decrypt(encrypted_text)
        click.echo(f'Decrypted text: {decrypted_text.decode()}')

    elif method == 'rsa':
        if key_file is None:
            click.echo("The RSA key file name is required for the RSA method.")
            return
        try:
            with open(key_file, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            decrypted_text = private_key.decrypt(
                encrypted_text,
                padding.PKCS1v15()
            )
            click.echo(f'Decrypted text: {decrypted_text.decode()}')
        except Exception as e:
            click.echo(f'Failed decrypt with RSA: {str(e)}')

    elif method == 'aes':
        if key_file is None or initialization_vector is None:
            click.echo("The AES key file name and IV are required for the AES method.")
            return
        try:
            with open(key_file, 'rb') as key_file:
                key = key_file.read()
            with open(initialization_vector, 'rb') as iv_file:
                iv = iv_file.read()
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
            click.echo(f'Decrypted text: {decrypted_text.rstrip(b" ").decode()}')
        except Exception as e:
            click.echo(f'Failed to encrypt with AES: {str(e)}')

if __name__ == '__main__':
    cli()