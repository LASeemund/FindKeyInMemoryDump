#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16

int aes_encrypt(uint8_t *key, const char *input_filename, const char *output_filename) {
    FILE *ifp = fopen(input_filename, "rb");
    FILE *ofp = fopen(output_filename, "wb");
    
    if (!ifp || !ofp) {
        printf("Failed to open file");
        return(-99);
    }

    AES_KEY encryptKey;
    if (AES_set_encrypt_key((uint8_t*) key, 256, &encryptKey) < 0) {
        return(-99);
    }

    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];
	unsigned char iv[AES_BLOCK_SIZE] = {0x07,0x07,0x07,0x00,0x43,0x00,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x56,0x57};
    
	for(int i=0; i<32; i++){
		printf("%02X ", encryptKey.rd_key[i]);
	}
	
    // Write IV to the output file
    fwrite(iv, 1, AES_BLOCK_SIZE, ofp);

    while (1) {
        int bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);
        if (bytes_read <= 0) break;

        AES_cfb128_encrypt(indata, outdata, bytes_read, &encryptKey, iv, &bytes_read, AES_ENCRYPT);
        fwrite(outdata, 1, bytes_read, ofp);
    }
	scanf("Pause");

    fclose(ifp);
    fclose(ofp);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return(-99);
    }

	uint8_t key[32] = {0x43, 0x00, 0x4B,  0x45, 0x49,  0x4C,  0x41,  0x00,  0x54, 
							0x45,  0x00,  0x41,  0x4D,  0x4F,  0x00,  0x00,  0x53,  0x4F, 
							0x4D,  0x4F,  0x53,  0x00,  0x44,  0x4F,  0x00,  0x53,  0x45, 
							0x4E,  0x48,  0x4F,  0x52,  0x00 };
	
    const char *input_filename = argv[1];
    char output_filename[256];

    snprintf(output_filename, sizeof(output_filename), "%s.enc", input_filename);
    
    aes_encrypt(key, input_filename, output_filename);
    
    printf("File encrypted successfully, output file: %s\n", output_filename);

    return(-99);
}
