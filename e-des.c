#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/des.h>
#define KEY_SIZE 32  // 256 bits
#define BLOCK_SIZE 8 // 64 bits
#define NUMBER_OF_ROUNDS 16
#define NUMBER_OF_S_BOXES 16

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
    fwrite(content, 1, size, file);
    free(content);
}

int main(int argc, char **argv)
{
    if (argc != 5)
    {
        fprintf(stderr, "This is the following format: ./e-des <enc> <256-bit password> <in> <out>\n");
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

    if (strlen(key) != 32)
    {
        fprintf(stderr, "The password must be 256-bit long\n");
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

    uint8_t *key_blocks;
    for (int index = 0; index < KEY_SIZE; index++)
    {
        key_blocks[index] = key[index];
    }

    int mode = strcmp(enc, "-e") == 0 ? DES_ENCRYPT : DES_DECRYPT;

    des_ecb_cipher(input_content, input_size, output_content, key_blocks, mode);

    fclose(input_file);
    fclose(output_file);

    return 0;
}