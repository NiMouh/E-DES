#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
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
    
    ftruncate(fileno(file), 0); // clear the file

    fwrite(content, 1, size, file);
    free(content);
}

uint8_t* add_padding(const uint8_t *plaintext, size_t plaintext_length, size_t *padded_length) {
    // Calculate the new padded length
    size_t padding_bytes = BLOCK_SIZE - (plaintext_length % BLOCK_SIZE);
    *padded_length = plaintext_length + padding_bytes;

    // Allocate memory for padded_plaintext
    uint8_t *padded_plaintext = (uint8_t*)malloc(*padded_length);

    if (padded_plaintext == NULL) { // memory allocation error
        return NULL;
    }

    // Copy the original plaintext
    memcpy(padded_plaintext, plaintext, plaintext_length);

    // Add padding
    for (size_t i = plaintext_length; i < *padded_length; i++) {
        padded_plaintext[i] = '0' + padding_bytes;
    }

    return padded_plaintext;
}

uint8_t* remove_padding(const uint8_t *padded_plaintext, size_t padded_length, size_t *plaintext_length) {
    // Check if the input length is valid
    if (padded_length % BLOCK_SIZE != 0 || padded_length == 0) {
        printf("Invalid padded length: %zu\n", padded_length);
        return NULL;  // Invalid padded length
    }

    // Get the last value of the padded plaintext
    size_t padding_value = padded_plaintext[padded_length - 1] - '0';

    if (padding_value < 1 || padding_value > BLOCK_SIZE) {
        printf("Invalid padding value: %zu\n", padding_value);
        return NULL;  // Invalid padding value
    }

    // Calculate the length of the plaintext (excluding padding)
    *plaintext_length = padded_length - padding_value;

    // Allocate memory for the plaintext
    uint8_t *plaintext = (uint8_t*)malloc(*plaintext_length);

    if (plaintext == NULL) { // memory allocation error
        return NULL;
    }

    // Copy the original plaintext (excluding padding)
    memcpy(plaintext, padded_plaintext, *plaintext_length);

    return plaintext;
}

uint8_t* encrypt(const uint8_t *plaintext, const uint8_t *key)
{
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key, BLOCK_SIZE);

    DES_set_odd_parity(&des_key);
    DES_set_key_checked(&des_key, &schedule);

    // Add padding
    size_t plaintext_len = strlen((char *)plaintext);
    size_t padded_len;
    uint8_t *padded_plaintext = add_padding(plaintext, plaintext_len, &padded_len);

    // Declare ciphertext
    size_t ciphertext_len = (padded_len / BLOCK_SIZE) * BLOCK_SIZE;
    uint8_t *ciphertext = (uint8_t *)malloc(ciphertext_len);
    if (ciphertext == NULL) { // memory allocation error
        return NULL;
    }

    // Encrypt
    for (size_t block_index = 0; block_index < padded_len; block_index += BLOCK_SIZE)
    {
        DES_ecb_encrypt((DES_cblock *)(padded_plaintext + block_index), (DES_cblock *)(ciphertext + block_index), &schedule, DES_ENCRYPT);
    }

    free(padded_plaintext);

    return ciphertext;
}

uint8_t* decrypt(const uint8_t *ciphertext, const uint8_t *key)
{
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key, BLOCK_SIZE);

    DES_set_odd_parity(&des_key);
    DES_set_key_checked(&des_key, &schedule);

    // Declare plaintext
    size_t ciphertext_len = strlen((char *)ciphertext);
    size_t padded_plaintext_len = ciphertext_len;
    uint8_t *padded_plaintext = (uint8_t *)malloc(padded_plaintext_len);
    if (padded_plaintext == NULL) { // memory allocation error
        return NULL;
    }

    // Decrypt
    for (size_t i = 0; i < ciphertext_len; i += BLOCK_SIZE)
    {
        DES_ecb_encrypt((DES_cblock *)(ciphertext + i), (DES_cblock *)(padded_plaintext + i), &schedule, DES_DECRYPT);
    }

    // Remove padding
    size_t plaintext_len;
    uint8_t *plaintext = remove_padding(padded_plaintext, padded_plaintext_len, &plaintext_len);

    free(padded_plaintext);

    return plaintext;
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
    uint8_t *output_content;

    uint8_t *key_block = malloc(BLOCK_SIZE);
    for (int index = 0; index < BLOCK_SIZE; index++)
    {
        key_block[index] = key[index];
    }

    int cipher = strcmp(enc, "-e") == 0 ? DES_ENCRYPT : DES_DECRYPT;

    if (cipher)
    {
        output_content = encrypt(input_content, key_block);
    }
    else
    {
        output_content = decrypt(input_content, key_block);
    }

    size_t output_size = strlen((char *)output_content);

    write_file(output_file, output_content, output_size);

    fclose(input_file);
    fclose(output_file);

    return 0;
}