#pip install cryptography

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import sys
#import os

def criptografar_arquivo(nome_arquivo, chave_hex):
    salvar_em_arquivo = True
    
    # Convertendo a chave hex em bytes
    chave = bytes.fromhex(chave_hex)
    
    # Verificando se a chave tem 256 bits (32 bytes)
    if len(chave) != 32:
        chave = bytearray(chave)
        print("Warning: A chave deve ser uma string hexadecimal de 64 caracteres (256 bits). \n Será feito o padding da chave.")
        for i in range(len(chave),32):
            chave.append(0x00)
        chave = bytes(chave)
    
    #Gera um IV
    #iv = os.urandom(16)# Gerar um IV aleatório de 128 bits (16 bytes)
    iv = bytes.fromhex("07070700505954484F4E000707075657")
    
    # Configurando o cifrador AES-256-CBC
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    
    if(type(nome_arquivo) != type("str")):
        raise ValueError("Error: nome_arquivo tem que ser uma string.")
    try:
        # Lendo o conteúdo do arquivo
        with open(nome_arquivo, 'rb') as f:
            arquivo_original = f.read()
    except:
        print(f"Warning: arquivo não encontrado, a string \'{nome_arquivo}\' será usada no lugar.")
        arquivo_original = bytes(nome_arquivo, 'ascii')
        salvar_em_arquivo = False
    
    # Padding do conteúdo do arquivo para garantir que seu tamanho seja um múltiplo de 128 bits
    padder = padding.PKCS7(128).padder()
    arquivo_padded = padder.update(arquivo_original) + padder.finalize()
    
    # Criptografando o conteúdo do arquivo
    encryptor = cipher.encryptor()
    print(f"iv: {iv.hex().upper()}\nkey: {chave.hex().upper()}")
    input("")
    arquivo_criptografado = encryptor.update(arquivo_padded) + encryptor.finalize()
    
    if(salvar_em_arquivo):
        # Salvando o arquivo cifrado
        nome_arquivo_cifrado = nome_arquivo + ".aes"
        with open(nome_arquivo_cifrado, 'wb') as f:
            f.write(iv + arquivo_criptografado)  # Prependendo o IV ao conteúdo criptografado
        print(f"Arquivo com o nome {nome_arquivo_cifrado} criado.")
        return nome_arquivo_cifrado
    else:
        print(f"Saida: {arquivo_criptografado}")
        return 0
    return 0

#string to key
#converte uma string para hex
def s2k(chave):
    if(len(chave) % 2 != 0):
        chave = '0' + chave
    return chave

if __name__ == "__main__":
    if len(sys.argv)-1 != 1:
        # Exemplo de uso
        chave_hex = 0x5657
        chave_hex = hex(chave_hex)[2:]
        nome_arquivo_criptografado = criptografar_arquivo('5657', s2k(chave_hex))
    else:
        chave_hex =  "505954484F4E0000524F4D414E4F5301480000544500414D4F004B45494C4100"
        nome_arquivo_criptografado = criptografar_arquivo(sys.argv[1], chave_hex)
