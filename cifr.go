
// go build -gcflags="all=-N -l"

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

func s2k(chave string) string {
	if len(chave)%2 != 0 {
		chave = "0" + chave
	}
	return chave
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func criptografarArquivo(nomeArquivo string, chaveHex string) (string, error) {
	salvarEmArquivo := true

	// Converte a chave hex em bytes
	chaveHex = s2k(chaveHex)
	chave, err := hex.DecodeString(chaveHex)
	if err != nil {
		return "", fmt.Errorf("erro ao converter chave hex: %w", err)
	}

	// Verifica se a chave tem 256 bits (32 bytes)
	if len(chave) != 32 {
		fmt.Println("Warning: A chave deve ser uma string hexadecimal de 64 caracteres (256 bits).")
		fmt.Println("Será feito o padding da chave.")
		if len(chave) < 32 {
			chave = append(chave, bytes.Repeat([]byte{0x00}, 32-len(chave))...)
		}
	}

	// IV fixo
	iv, err := hex.DecodeString("07070700505954484F4E000707075657")
	if err != nil {
		return "", fmt.Errorf("erro ao converter IV: %w", err)
	}

	// Lê o arquivo; se não existir, usa a string como conteúdo
	arquivoOriginal, err := os.ReadFile(nomeArquivo)
	if err != nil {
		fmt.Printf("Warning: arquivo não encontrado, a string '%s' será usada no lugar.\n", nomeArquivo)
		arquivoOriginal = []byte(nomeArquivo)
		salvarEmArquivo = false
	}

	// Padding PKCS7
	arquivoPadded := pkcs7Pad(arquivoOriginal, aes.BlockSize)

	// Criptografia AES-256-CBC
	block, err := aes.NewCipher(chave)
	if err != nil {
		return "", fmt.Errorf("erro ao criar cipher AES: %w", err)
	}

	if len(iv) != aes.BlockSize {
		return "", fmt.Errorf("IV inválido: tamanho esperado %d bytes, obtido %d", aes.BlockSize, len(iv))
	}

	criptografado := make([]byte, len(arquivoPadded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(criptografado, arquivoPadded)

	fmt.Printf("iv: %X\nkey: %X\n", iv, chave)

	time.Sleep(60 * 5 * time.Second)

	if salvarEmArquivo {
		nomeArquivoCifrado := nomeArquivo + ".aes"
		conteudo := append(iv, criptografado...)
		if err := os.WriteFile(nomeArquivoCifrado, conteudo, 0644); err != nil {
			return "", fmt.Errorf("erro ao salvar arquivo cifrado: %w", err)
		}
		fmt.Printf("Arquivo com o nome %s criado.\n", nomeArquivoCifrado)
		return nomeArquivoCifrado, nil
	}

	fmt.Printf("Saida: %X\n", criptografado)
	return "", nil
}

func main() {
	if len(os.Args)-1 != 1 {
		fmt.Println("Erro na passagem de parâmetros!")
        os.Exit(1)
	} else {
		//chaveHex := "505954484F4E0000524F4D414E4F5301480000544500414D4F004B45494C4100"
		chaveHex := "0524f4d414e4f53014080005224f4d414e4f530140800524f4d414e4f5301408"

		// Se houver aspas/ espaços extras, remove
		arquivo := strings.TrimSpace(os.Args[1])

		_, err := criptografarArquivo(arquivo, chaveHex)
		if err != nil {
			fmt.Println("Erro:", err)
			os.Exit(1)
		}

		for i := 0; i < 10000000; i++ {
			a := i * 7
			_ = a
		}

		fmt.Scanln()
	}
}
