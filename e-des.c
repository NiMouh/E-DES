#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/des.h>
#define KEY_SIZE 32  // 256 bits
#define BLOCK_SIZE 8 // 64 bits
#define NUMBER_OF_ROUNDS 16
#define NUMBER_OF_S_BOXES 16

// E-DES Implementation

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

    ftruncate(fileno(file), 0); // clear the file

    fwrite(content, 1, size, file);
    free(content);
}

uint8_t *add_padding(const uint8_t *plaintext, size_t plaintext_length, size_t *padded_length)
{
    // Calculate the new padded length
    size_t padding_bytes = BLOCK_SIZE - (plaintext_length % BLOCK_SIZE);
    *padded_length = plaintext_length + padding_bytes;

    // Allocate memory for padded_plaintext
    uint8_t *padded_plaintext = (uint8_t *)malloc(*padded_length);

    if (padded_plaintext == NULL)
    { // memory allocation error
        return NULL;
    }

    // Copy the original plaintext
    memcpy(padded_plaintext, plaintext, plaintext_length);

    // Add padding
    for (size_t i = plaintext_length; i < *padded_length; i++)
    {
        padded_plaintext[i] = '0' + padding_bytes;
    }

    return padded_plaintext;
}

uint8_t *remove_padding(const uint8_t *padded_plaintext, size_t padded_length, size_t *plaintext_length)
{
    // Check if the input length is valid
    if (padded_length % BLOCK_SIZE != 0 || padded_length == 0)
    {
        printf("Invalid padded length: %zu\n", padded_length);
        return NULL; // Invalid padded length
    }

    // Get the last value of the padded plaintext
    size_t padding_value = padded_plaintext[padded_length - 1] - '0';

    if (padding_value < 1 || padding_value > BLOCK_SIZE)
    {
        printf("Invalid padding value: %zu\n", padding_value);
        return NULL; // Invalid padding value
    }

    // Calculate the length of the plaintext (excluding padding)
    *plaintext_length = padded_length - padding_value;

    // Allocate memory for the plaintext
    uint8_t *plaintext = (uint8_t *)malloc(*plaintext_length);

    if (plaintext == NULL)
    { // memory allocation error
        return NULL;
    }

    // Copy the original plaintext (excluding padding)
    memcpy(plaintext, padded_plaintext, *plaintext_length);

    return plaintext;
}

uint8_t *encrypt(const uint8_t *plaintext, const uint8_t *key)
{
    // Add padding
    size_t plaintext_len = strlen((char *)plaintext);
    size_t padded_len;
    uint8_t *padded_plaintext = add_padding(plaintext, plaintext_len, &padded_len);

    // TODO: Generate the S-Boxes from the key: generate_s_boxes(uint8_t *key)

    uint8_t *ciphertext = (uint8_t *)malloc(padded_len);

    for (size_t block_index = 0; block_index < padded_len; block_index += BLOCK_SIZE)
    {
        // Get the block from the padded plaintext
        uint8_t block[BLOCK_SIZE];
        memcpy(block, padded_plaintext + block_index, BLOCK_SIZE);
        printf("Block: %s\n", block);
        // Start the feistel network with the block and the key: feistel_network(uint8_t *block, uint8_t * s_boxes)
        // Copy the result to the ciphertext
    }

    free(padded_plaintext);

    return ciphertext;
}

uint8_t *feistel_network(const uint8_t *block, uint8_t *s_boxes)
{
    uint8_t ciphered_block[BLOCK_SIZE];

    // Split the block in two halves
    uint8_t L[BLOCK_SIZE / 2];
    uint8_t R[BLOCK_SIZE / 2];

    memcpy(L, block, BLOCK_SIZE / 2);
    memcpy(R, block + BLOCK_SIZE / 2, BLOCK_SIZE / 2);

    // For each round
    for (int round = 0; round < NUMBER_OF_ROUNDS; round++)
    {
        // Copy the right half to the left half
        memcpy(L, R, BLOCK_SIZE / 2);

        // Apply the feistel function to the right half
        uint8_t * feistel_result = feistel_function(R, s_boxes[round]);

        // XOR the left half with the feistel result
        for (int index = 0; index < BLOCK_SIZE / 2; index++)
        {
            R[index] = L[index] ^ feistel_result[index];
        }
    }

    // Swap the left and right halves
    memcpy(ciphered_block, R, BLOCK_SIZE / 2);
    memcpy(ciphered_block + BLOCK_SIZE / 2, L, BLOCK_SIZE / 2);

    return ciphered_block;
}

uint8_t * feistel_function(uint8_t * input_block, uint8_t * s_box){
    uint8_t output_block[BLOCK_SIZE / 2];

    uint8_t index = input_block[BLOCK_SIZE / 2 - 1];
    output_block[BLOCK_SIZE / 2 - 1] = s_box[index];
    for (size_t byte_index = BLOCK_SIZE / 2 - 2; byte_index >= 0; byte_index--)
    {
        index += input_block[byte_index];
        output_block[byte_index] = s_box[index];
    }

    return output_block;
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
    uint8_t *output_content;

    uint8_t *key_blocks;
    for (int index = 0; index < KEY_SIZE; index++)
    {
        key_blocks[index] = key[index];
    }

    int cipher = strcmp(enc, "-e") == 0 ? DES_ENCRYPT : DES_DECRYPT;

    if (cipher)
    {
        output_content = encrypt(input_content, key_blocks);
    }
    else
    {
        output_content = decrypt(input_content, key_blocks);
    }

    size_t output_size = strlen((char *)output_content);

    write_file(output_file, output_content, output_size);

    fclose(input_file);
    fclose(output_file);

    return 0;
}