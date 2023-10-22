#include "implementation.h"
#include <iostream>
#include <cstring>
#include <cstdlib>

void encrypt(const uint8_t *plaintext, const uint8_t *password, uint8_t **ciphertext, size_t *ciphertext_size)
{
    size_t plaintext_size = std::strlen((char *)plaintext);

    uint8_t *padded_plaintext;
    size_t padded_plaintext_size;
    add_padding(plaintext, plaintext_size, &padded_plaintext, &padded_plaintext_size);

    struct s_box *sboxes = (struct s_box *)std::malloc(sizeof(struct s_box) * NUMBER_OF_ROUNDS);

    if (sboxes == nullptr) // memory allocation error
    {
        std::cerr << "Error allocating memory for sboxes" << std::endl;
        std::exit(1);
    }

    uint8_t *key = (uint8_t *)std::malloc(KEY_SIZE);

    if (key == nullptr) // memory allocation error
    {
        std::cerr << "Error allocating memory for key" << std::endl;
        std::exit(1);
    }

    generate_key(password, &key);

    generate_sboxes(key, sboxes);

    *ciphertext = (uint8_t *)std::malloc(padded_plaintext_size);

    if (*ciphertext == nullptr) // Check for memory allocation error
    {
        std::cerr << "Error allocating memory for ciphertext" << std::endl;
        std::exit(1);
    }

    for (size_t block_index = 0; block_index < padded_plaintext_size; block_index += BLOCK_SIZE)
    {
        uint8_t *block = (uint8_t *)std::malloc(BLOCK_SIZE);
        std::memcpy(block, padded_plaintext + block_index, BLOCK_SIZE);

        uint8_t *cipher_block = (uint8_t *)std::malloc(BLOCK_SIZE);
        feistel_network(block, sboxes, &cipher_block);

        std::memcpy(*ciphertext + block_index, cipher_block, BLOCK_SIZE);

        // Free the block and cipher_block memory
        std::free(block);
        std::free(cipher_block);
    }

    // Update the ciphertext size
    *ciphertext_size = padded_plaintext_size;

    // Free memory
    std::free(sboxes);
    std::free(padded_plaintext);
}

void decrypt(const uint8_t *ciphertext, const size_t ciphertext_size, const uint8_t *password, uint8_t **plaintext, size_t *plaintext_size)
{
    struct s_box *sboxes = (struct s_box *)std::malloc(sizeof(struct s_box) * NUMBER_OF_ROUNDS);

    if (sboxes == nullptr) // memory allocation error
    {
        std::cerr << "Error allocating memory for sboxes" << std::endl;
        std::exit(1);
    }

    uint8_t *key = (uint8_t *)std::malloc(KEY_SIZE);

    if (key == nullptr) // memory allocation error
    {
        std::cerr << "Error allocating memory for key" << std::endl;
        std::exit(1);
    }

    generate_key(password, &key);

    generate_sboxes(key, sboxes);

    size_t padded_plaintext_size = ciphertext_size;
    uint8_t *padded_plaintext = (uint8_t *)std::malloc(padded_plaintext_size);

    if (padded_plaintext == nullptr) // memory allocation error
    {
        std::cerr << "Error allocating memory for padded plaintext" << std::endl;
        std::exit(1);
    }

    for (size_t block_index = 0; block_index < ciphertext_size; block_index += BLOCK_SIZE)
    {
        uint8_t *block = (uint8_t *)std::malloc(BLOCK_SIZE);
        std::memcpy(block, ciphertext + block_index, BLOCK_SIZE);

        uint8_t *decipher_block = (uint8_t *)std::malloc(BLOCK_SIZE);
        inverse_feistel_network(block, sboxes, &decipher_block);

        std::memcpy(padded_plaintext + block_index, decipher_block, BLOCK_SIZE);

        std::free(block);
        std::free(decipher_block);
    }

    remove_padding(padded_plaintext, padded_plaintext_size, plaintext, plaintext_size);

    // Free memory
    std::free(sboxes);
    std::free(padded_plaintext);
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <-e/-d> <password>" << std::endl;
        std::exit(1);
    }

    // Read the password
    uint8_t *password = (uint8_t *)argv[2];

    // Read the bytes from stdin
    uint8_t *readed_bytes = (uint8_t *)std::malloc(sizeof(uint8_t) * MAX_BYTES);

    if (readed_bytes == nullptr) // memory allocation error
    {
        std::cerr << "Error allocating memory for readed bytes" << std::endl;
        std::exit(1);
    }

    size_t number_of_readed_bytes;
    read_bytes(readed_bytes, &number_of_readed_bytes);

    // Encrypt or decrypt
    int cipher = std::strcmp(argv[1], "-e") == 0;
    if (cipher)
    {
        // Encrypt
        uint8_t *ciphertext;
        size_t ciphertext_size;
        encrypt(readed_bytes, password, &ciphertext, &ciphertext_size);

        // Write the ciphertext to stdout
        write_bytes(ciphertext, ciphertext_size);

        // Free memory
        std::free(ciphertext);
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
        std::free(plaintext);
    }

    return 0;
}