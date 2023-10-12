#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/des.h>
#define BLOCK_SIZE 8 // 64 bits

// DES ECB Mode
uint8_t *read_file(FILE *file, size_t *size)
{
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t *content = malloc(*size);
    fread(content, 1, *size, file);

    return content;
}

void write_file(FILE *file, uint8_t *content, size_t size)
{
    if (content == NULL)
    {
        fprintf(stderr, "Não foi possível ler o ficheiro!\n");
        exit(0);
    }

    fwrite(content, 1, size, file);
    free(content);
}


void encrypt(const uint8_t *plaintext, uint8_t *ciphertext, const uint8_t *key)
{
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key, BLOCK_SIZE);

    DES_set_odd_parity(&des_key);
    DES_set_key_checked(&des_key, &schedule);

    // Add padding
    size_t plaintext_len = strlen((char *)plaintext);
    size_t padded_len = plaintext_len + (BLOCK_SIZE - (plaintext_len % BLOCK_SIZE));

    uint8_t *padded_plaintext = calloc(padded_len, sizeof(uint8_t));
    memcpy(padded_plaintext, plaintext, plaintext_len);
    for (size_t i = plaintext_len; i < padded_len; i++)
    {
        padded_plaintext[i] = (uint8_t)(padded_len - plaintext_len);
    }

    // Encrypt
    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE)
    {
        DES_ecb_encrypt((DES_cblock *)(padded_plaintext + i), (DES_cblock *)(ciphertext + i), &schedule, DES_ENCRYPT);
    }

    free(padded_plaintext);
}

void decrypt(const uint8_t *ciphertext, const uint8_t *key, uint8_t *plaintext)
{
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key, BLOCK_SIZE);

    DES_set_odd_parity(&des_key);
    DES_set_key_checked(&des_key, &schedule);

    // Decrypt
    size_t ciphertext_len = strlen((char *)ciphertext);
    for (size_t i = 0; i < ciphertext_len; i += BLOCK_SIZE)
    {
        DES_ecb_encrypt((DES_cblock *)(ciphertext + i), (DES_cblock *)(plaintext + i), &schedule, DES_DECRYPT);
    }

    // Remove padding
    size_t plaintext_len = ciphertext_len;
    uint8_t padding_len = plaintext[plaintext_len - 1];
    plaintext_len -= padding_len;

    plaintext[plaintext_len] = '\0';
}

int main(int argc, char **argv){
    if (argc != 5)
    {
        fprintf(stderr, "This is the following format: ./des <enc> <8-byte password> <in> <out>\n");
        exit(0);
    }

    char *enc = argv[1];
    char *key = argv[2];
    char *input = argv[3];
    char *output = argv[4];

    if (strcmp(enc, "-e") != 0 && strcmp(enc, "-d") != 0)
    {
        fprintf(stderr, "The first argument must be '-e' or '-d'\n");
        exit(0);
    }

    if (strlen(key) != 8)
    {
        fprintf(stderr, "The password must be 64-bit long\n");
        exit(0);
    }

    FILE *input_file = fopen(input, "rb");
    FILE *output_file = fopen(output, "wb");

    if (input_file == NULL || output_file == NULL)
    {
        fprintf(stderr, "Não foi possível criar/ler o ficheiro!\n");
        exit(0);
    }

    size_t input_size;
    uint8_t *input_content = read_file(input_file, &input_size);

    size_t output_size = input_size;
    uint8_t *output_content = malloc(output_size);

    uint8_t *key_block = malloc(BLOCK_SIZE);
    for (int index = 0; index < BLOCK_SIZE; index++)
    {
        key_block[index] = key[index];
    }

    int cipher = strcmp(enc, "-e") == 0 ? DES_ENCRYPT : DES_DECRYPT;

    if (cipher)
    {
        encrypt(input_content, output_content, key_block);
    }
    else
    {
        decrypt(input_content, key_block, output_content);
    }

    write_file(output_file, output_content, output_size);

    fclose(input_file);
    fclose(output_file);

    return 0;
}