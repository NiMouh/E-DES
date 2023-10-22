#include "implementation.h"

/**
 * Encrypt Function, receives the plaintext, the password and a pointer to the ciphertext
 *
 * @param plaintext the plaintext (uint8_t array)
 * @param password the password (uint8_t array)
 * @param ciphertext pointer to the ciphertext (uint8_t array)
 * @param ciphertext_size pointer to the ciphertext size (size_t)
 */
void encrypt(const uint8_t *plaintext, const uint8_t *password, uint8_t **ciphertext, size_t *ciphertext_size)
{
    size_t plaintext_size = strlen((char *)plaintext);

    uint8_t *padded_plaintext;
    size_t padded_plaintext_size;
    add_padding(plaintext, plaintext_size, &padded_plaintext, &padded_plaintext_size);

    struct s_box *sboxes = (struct s_box *)malloc(sizeof(struct s_box) * NUMBER_OF_ROUNDS);

    if (sboxes == NULL) // memory allocation error
    {
        printf("Error allocating memory for sboxes\n");
        exit(1);
    }

    uint8_t *key = (uint8_t *) malloc(KEY_SIZE);

    if (key == NULL) // memory allocation error
    {
        printf("Error allocating memory for key\n");
        exit(1);
    }

    generate_key(password, &key);

    generate_sboxes(key, sboxes);

    *ciphertext = (uint8_t *)malloc(padded_plaintext_size);

    if (*ciphertext == NULL) // Check for memory allocation error
    {
        printf("Error allocating memory for ciphertext\n");
        exit(1);
    }

    for (size_t block_index = 0; block_index < padded_plaintext_size; block_index += BLOCK_SIZE)
    {
        uint8_t *block = (uint8_t *)malloc(BLOCK_SIZE);
        memcpy(block, padded_plaintext + block_index, BLOCK_SIZE);

        uint8_t *cipher_block = (uint8_t *)malloc(BLOCK_SIZE);
        feistel_network(block, sboxes, &cipher_block);

        memcpy(*ciphertext + block_index, cipher_block, BLOCK_SIZE);

        // Free the block and cipher_block memory
        free(block);
        free(cipher_block);
    }

    // Update the ciphertext size
    *ciphertext_size = padded_plaintext_size;

    // Free memory
    free(sboxes);
    free(padded_plaintext);
}

/**
 * Decrypt Function, receives the ciphertext, the key and a pointer to the plaintext
 *
 * @param ciphertext the ciphertext (uint8_t array)
 * @param password the password (uint8_t array)
 * @param plaintext pointer to the plaintext (uint8_t array)
 * @param plaintext_size pointer to the plaintext size (size_t)
 */
void decrypt(const uint8_t *ciphertext, const size_t ciphertext_size, const uint8_t *password, uint8_t **plaintext, size_t *plaintext_size)
{
    struct s_box *sboxes = (struct s_box *)malloc(sizeof(struct s_box) * NUMBER_OF_ROUNDS);

    if (sboxes == NULL) // memory allocation error
    {
        printf("Error allocating memory for sboxes\n");
        exit(1);
    }

    uint8_t *key = (uint8_t *) malloc(KEY_SIZE);

    if (key == NULL) // memory allocation error
    {
        printf("Error allocating memory for key\n");
        exit(1);
    }

    generate_key(password, &key);

    generate_sboxes(key, sboxes);

    size_t padded_plaintext_size = ciphertext_size;
    uint8_t *padded_plaintext = (uint8_t *) malloc(padded_plaintext_size);

    if (padded_plaintext == NULL) // memory allocation error
    {
        printf("Error allocating memory for padded plaintext\n");
        exit(1);
    }

    for (size_t block_index = 0; block_index < ciphertext_size; block_index += BLOCK_SIZE)
    {
        uint8_t *block = (uint8_t *) malloc(BLOCK_SIZE);
        memcpy(block, ciphertext + block_index, BLOCK_SIZE);

        uint8_t *decipher_block = (uint8_t *) malloc(BLOCK_SIZE);
        inverse_feistel_network(block, sboxes, &decipher_block);

        memcpy(padded_plaintext + block_index, decipher_block, BLOCK_SIZE);

        free(block);
        free(decipher_block);
    }

    remove_padding(padded_plaintext, padded_plaintext_size, plaintext, plaintext_size);

    // Free memory
    free(sboxes);
    free(padded_plaintext);
}

/**
 * Main function, it receives the arguments and calls the encrypt or decrypt function
 *
 * @param argc number of arguments
 * @param argv arguments
 *
 * @return 0 if the program runs without errors, 1 otherwise
 */
int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <-e/-d> <password>\n", argv[0]);
        exit(1);
    }

    // Read the password
    uint8_t *password = (uint8_t *)argv[2];

    // Read the bytes from stdin
    uint8_t *readed_bytes = (uint8_t *) malloc(sizeof(uint8_t) * MAX_BYTES);

    if (readed_bytes == NULL) // memory allocation error
    {
        printf("Error allocating memory for readed bytes\n");
        exit(1);
    }

    size_t number_of_readed_bytes;
    read_bytes(readed_bytes, &number_of_readed_bytes);

    // Encrypt or decrypt
    int cipher = strcmp(argv[1], "-e") == 0;
    if (cipher)
    {
        // Encrypt
        uint8_t *ciphertext;
        size_t ciphertext_size;
        encrypt(readed_bytes, password, &ciphertext, &ciphertext_size);

        // Write the ciphertext to stdout
        write_bytes(ciphertext, ciphertext_size);

        // Free memory
        free(ciphertext);
    }
    else
    {
        // Decrypt
        uint8_t *plaintext;
        size_t plaintext_size;
        decrypt(readed_bytes, number_of_readed_bytes, password, &plaintext, &plaintext_size);

        // Write the plaintext to stdout
        write_bytes(plaintext, plaintext_size);

        // Free memory
        free(plaintext);
    }

    return 0;
}