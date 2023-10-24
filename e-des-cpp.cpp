#include "implementation.h"
#include <iostream>
#include <cstring>
#include <cstdlib>

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