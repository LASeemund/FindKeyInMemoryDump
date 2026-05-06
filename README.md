# Busca de Chaves Criptográficas em Despejo de Memória

Este repositório reúne a implementação desenvolvida para um Trabalho de Conclusão de Curso (TCC) cujo objetivo é **identificar chaves criptográficas armazenadas em memória volátil a partir de um despejo de memória**.

A proposta do projeto é estudar, de forma prática, como uma chave AES-256 pode ser localizada quando seu conteúdo aparece em memória junto com a expansão da chave, permitindo comparar os dados observados no arquivo com o padrão esperado da rotina de *key schedule* do AES.

## Objetivo

O principal objetivo é demonstrar uma abordagem de análise de memória voltada à recuperação de material criptográfico, com foco em:

* localizar chaves AES-256 em arquivos de memória ou dados brutos;
* expandir a chave e comparar o *round key schedule* com o conteúdo do despejo;
* validar, em ambiente controlado, a viabilidade da identificação de chaves em memória.

## Estrutura do repositório

* `cifr.py` — script em Python para cifrar arquivos com AES-256-CBC.
* `cifr.c` — implementação em C para cifragem com OpenSSL.
* `cifr.go` — implementação em Golang para cifragem.
* `findkey.c` — programa principal para varrer o arquivo e buscar a chave expandida em memória.
* `tccExpandedkey.c` — código de apoio para gerar e exibir a expansão da chave AES-256.

## Descrição dos arquivos

### `cifr.py`

Script em Python que utiliza a biblioteca `cryptography` para cifrar arquivos com **AES-256-CBC**. Caso o nome do arquivo não exista, a string informada é usada como entrada, permitindo testes rápidos.

### `cifr.c`

Versão em C da rotina de cifragem, usando OpenSSL. O código emprega AES com chave de 256 bits e grava o IV no início do arquivo de saída.

### `cifr.go`

Implementação em Go de uma rotina de cifragem utilizando a biblioteca padrão da linguagem. O programa realiza a cifragem de arquivos com AES-256 no modo CBC, aplicando padding PKCS#7 e armazenando o vetor de inicialização (IV) no início do arquivo gerado.

### `findkey.c`

Programa responsável por percorrer o arquivo carregado em memória e procurar padrões compatíveis com a expansão de uma chave AES-256.

O funcionamento geral é:

1. o arquivo é carregado integralmente na memória;
2. várias *threads* analisam blocos distintos do conteúdo;
3. para cada posição candidata, os 32 primeiros bytes são tratados como possível chave;
4. a chave é expandida;
5. a expansão é comparada com os bytes seguintes do arquivo;
6. caso haja correspondência, a posição da chave é reportada.

Esse processo simula a busca de material criptográfico em um despejo de memória.

### `tccExpandedkey.c`

Arquivo auxiliar para teste e validação da função de expansão de chave do AES. Ele imprime a chave expandida a partir de uma chave fixa de 256 bits.

Serve como referência para conferência do comportamento do algoritmo implementado nos demais códigos.

## Dependências

### Python

* Python 3.x
* Biblioteca `cryptography`

### C

* GCC ou compilador compatível
* Biblioteca OpenSSL
* Suporte a `pthread`

### Golang

* Compilador Golang

## Fluxo experimental do projeto

O experimento foi organizado da seguinte forma:

1. uma chave AES-256 é definida no código;
2. um arquivo é cifrado com essa chave;
3. o despejo de memória, é analisado;
4. o programa de busca tenta localizar uma sequência de 240 bytes correspondente à chave expandida;
5. ao encontrar correspondência, a posição é reportada.

## Observações técnicas

* O projeto foi desenvolvido com foco acadêmico e experimental.
* A implementação de busca usa múltiplas *threads* para acelerar a varredura do arquivo.
* O código de expansão da chave foi implementado manualmente para permitir comparação direta com os bytes encontrados em memória.

## Resultado esperado

Ao executar a análise sobre um arquivo que contenha a chave e sua expansão, o programa pode identificar o offset onde o material criptográfico está presente e imprimir a chave expandida encontrada.

## Aplicação no TCC

Este repositório apoia o estudo de técnicas de **análise forense de memória** e **recuperação de chaves criptográficas**, mostrando de maneira prática como dados sensíveis podem permanecer acessíveis em memória após o uso de rotinas criptográficas.

## Autor
Lucas Alexandre Seemund.
Projeto desenvolvido para fins acadêmicos no contexto de TCC.
