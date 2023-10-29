#include "implementation.h"

/**
 * @file e-des.c
 * @brief Implementation of the e-des and des-ecb modes
 * 
 * This file contains the main function where the program starts.
 *
 * @author Ana Vidal (118408)
 * @author Simão Andrade (118345)
 * @date 2023-10-20
 */

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
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s <mode> <-e/-d> <password>\n", argv[0]);
        exit(1);
    }

    // Read the password
    uint8_t *password = (uint8_t *)argv[3];

    // Read the bytes from stdin
    uint8_t *readed_bytes = (uint8_t *)malloc(sizeof(uint8_t) * MAX_BYTES);

    if (readed_bytes == NULL) // memory allocation error
    {
        printf("Error allocating memory for readed bytes\n");
        exit(1);
    }

    size_t number_of_readed_bytes;
    read_bytes(readed_bytes, &number_of_readed_bytes);

    // Encrypt or decrypt
    int cipher = strcmp(argv[2], "-e") == 0;
    int decipher = strcmp(argv[2], "-d") == 0;

    // E-Des or DES-ECB mode
    int e_des_mode = strcmp(argv[1], "e-des") == 0;
    int ecb_des_mode = strcmp(argv[1], "des-ecb") == 0;

    if (cipher)
    { // Encrypt
        uint8_t *ciphertext;
        size_t ciphertext_size;

        if (e_des_mode)
        {
            encrypt(readed_bytes, password, &ciphertext, &ciphertext_size);
        }
        else if (ecb_des_mode)
        {
            ecb_encrypt(readed_bytes, password, &ciphertext, &ciphertext_size);
        }
        else
        {
            fprintf(stderr, "Usage: The only valid modes are e-des and des-ecb\n");
            exit(1);
        }

        // Write the ciphertext to stdout
        write_bytes(ciphertext, ciphertext_size);

        // Free memory
        free(ciphertext);
    }
    else if (decipher)
    { // Decrypt
        uint8_t *plaintext;
        size_t plaintext_size;

        if (e_des_mode)
        {
            decrypt(readed_bytes, number_of_readed_bytes, password, &plaintext, &plaintext_size);
        }
        else if (ecb_des_mode)
        {
            ecb_decrypt(readed_bytes, number_of_readed_bytes, password, &plaintext, &plaintext_size);
        }
        else
        {
            fprintf(stderr, "Usage: The only valid modes are e-des and des-ecb\n");
            exit(1);
        }

        // Write the plaintext to stdout
        write_bytes(plaintext, plaintext_size);

        // Free memory
        free(plaintext);
    }
    else
    {
        fprintf(stderr, "Usage: The only valid modes are -e and -d\n");
        exit(1);
    }

    return 0;
}