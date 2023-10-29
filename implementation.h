#ifndef __IMPLEMENTATION_H__
#define __IMPLEMENTATION_H__

/**
 * @file implementation.c
 * @brief Implementation of the e-des and des-ecb modes
 * 
 * This file contains the modules to the implementation of the e-des and des-ecb modes (using the openssl library). 
 *
 * @author Ana Vidal (118408)
 * @author Simão Andrade (118345)
 * @date 2023-10-20
 */

// Libraries for the implementation
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <openssl/sha.h>

// Libraries for performance testing
#include <openssl/des.h>
#include <time.h>

// Constants for the implementation
#define MAX_BYTES 1024
#define KEY_SIZE 32  // 256 bits
#define BLOCK_SIZE 8 // 64 bits
#define HALF_BLOCK_SIZE 4
#define NUMBER_OF_ROUNDS 16
#define NUMBER_OF_S_BOXES 16
#define S_BOX_SIZE 256 // 256 bytes
#define NUMBER_OF_BYTES_IN_ALL_S_BOXES (NUMBER_OF_S_BOXES * S_BOX_SIZE) // 4096 bytes

// Constants for the performance testing
#define NUMBER_OF_TESTS 100000
#define BUFFER_SIZE (4 * 1024)  // 4KiB buffer size

/**
 * Struct that represents a sbox
 *
 * @param sbox the sbox (uint8_t array)
 */
struct s_box
{
    uint8_t sbox[S_BOX_SIZE];
};

/**
 * Function that reads the bytes from stdin, it receives a pointer to the uint8_t array and a pointer to the size of the array
 *
 * @param readed_bytes pointer to the uint8_t array
 * @param number_of_readed_bytes pointer to the size of the array (size_t)
 */
void read_bytes(uint8_t *readed_bytes, size_t *number_of_readed_bytes);

/**
 * Function that writes the bytes to stdout, it receives a pointer to the uint8_t array and the number of bytes to write
 *
 * @param bytes_to_write pointer to the uint8_t array
 * @param number_of_bytes_to_write number of bytes to write (size_t)
 */
void write_bytes(const uint8_t *bytes_to_write, size_t number_of_bytes_to_write);

/**
 * Function that does the feistel function operation, it receives the input block and the sbox
 *
 * @param input_block the input block (uint8_t array)
 * @param s_box the sbox (uint8_t array)
 *
 * @return the output block (uint8_t array)
 *
 */
uint8_t *feistel_function(const uint8_t *input_block, const uint8_t *s_box);

/**
 * Function that handles the feistel network used to cipher, it receives the block that will be divided in two halfs, the sboxes and a pointer to the cipher block
 *
 * @param block the block (uint8_t array)
 * @param sboxes the sboxes (struct s_box array)
 * @param cipher_block pointer of the cipher block pointer (uint8_t array)
 */
void feistel_network(const uint8_t *block, const struct s_box *sboxes, uint8_t **cipher_block);

/**
 * Function that handles the inverse feistel network used to decipher, it receives the block that will be divided in two halfs, the sboxes and a pointer to the cipher block
 *
 * @param block the block (uint8_t array)
 * @param sboxes the sboxes (struct s_box array)
 * @param cipher_block pointer of the cipher block pointer (uint8_t array)
 */
void inverse_feistel_network(const uint8_t *block, const struct s_box *sboxes, uint8_t **cipher_block);

/**
 * Function that generates the key from the password, using SHA256
 *
 * @param password the password (uint8_t array)
 * @param key pointer to the key (uint8_t array)
 */
void generate_key(const uint8_t *password, uint8_t *key);

/**
 * Function that generates the single sbox by the key
 * 
 * @param password the password (uint8_t array)
 * @param single_sbox pointer to the single sbox (uint8_t array)
*/
void generate_single_sbox(const uint8_t *password, uint8_t *single_sbox);

/**
 * Function that will apply the round robin algorithm to shuffle the bytes
 * 
 * @param array the array (uint8_t array)
 * @param size the size of the array (size_t)
*/
void round_robin_shuffle(uint8_t *array, size_t size);

/**
 * Function that generates the sboxes from the password
 *
 * @param password the password (uint8_t array)
 * @param sboxes pointer to the sboxes (struct s_box array)
 */
void generate_sboxes(const uint8_t *password, struct s_box *sboxes);

/**
 * Function that will apply the PCKS#7 padding to the plaintext, it receives the plaintext, the plaintext length, a pointer to the padded plaintext and a pointer to the padded length
 *
 * @param plaintext the plaintext (uint8_t array)
 * @param plaintext_length the plaintext length (size_t)
 * @param padded_plaintext pointer to the padded plaintext (uint8_t array)
 * @param padded_length pointer to the padded length (size_t)
 */
void add_padding(const uint8_t *plaintext, size_t plaintext_length, uint8_t **padded_plaintext, size_t *padded_length);

/**
 * Function that will remove the PCKS#7 padding from the padded plaintext, it receives the padded plaintext, the padded plaintext length, a pointer to the plaintext and a pointer to the plaintext length
 *
 * @param padded_plaintext the padded plaintext (uint8_t array)
 * @param padded_length the padded plaintext length (size_t)
 * @param plaintext pointer to the plaintext (uint8_t array)
 * @param plaintext_length pointer to the plaintext length (size_t)
 */
void remove_padding(const uint8_t *padded_plaintext, size_t padded_length, uint8_t **plaintext, size_t *plaintext_length);

/**
 * Encrypt Function, receives the plaintext, the password and a pointer to the ciphertext
 *
 * @param plaintext the plaintext (uint8_t array)
 * @param password the password (uint8_t array)
 * @param ciphertext pointer to the ciphertext (uint8_t array)
 * @param ciphertext_size pointer to the ciphertext size (size_t)
 */
void encrypt(const uint8_t *plaintext, const uint8_t *password, uint8_t **ciphertext, size_t *ciphertext_size);

/**
 * Decrypt Function, receives the ciphertext, the key and a pointer to the plaintext
 *
 * @param ciphertext the ciphertext (uint8_t array)
 * @param password the password (uint8_t array)
 * @param plaintext pointer to the plaintext (uint8_t array)
 * @param plaintext_size pointer to the plaintext size (size_t)
 */
void decrypt(const uint8_t *ciphertext, const size_t ciphertext_size, const uint8_t *password, uint8_t **plaintext, size_t *plaintext_size);

/**
 * ECB Encrypt Function, receives the plaintext, the password and a pointer to the ciphertext
 *
 * @param plaintext the plaintext (uint8_t array)
 * @param password the password (uint8_t array)
 * @param ciphertext pointer to the ciphertext (uint8_t array)
 * @param ciphertext_size pointer to the ciphertext size (size_t)
 *
 */
void ecb_encrypt(const uint8_t *plaintext, const uint8_t *password, uint8_t **ciphertext, size_t *ciphertext_size);

/**
 * ECB Decrypt Function, receives the ciphertext, the password and a pointer to the plaintext
 *
 * @param ciphertext the ciphertext (uint8_t array)
 * @param ciphertext_size the ciphertext size (size_t)
 * @param password the password (uint8_t array)
 * @param plaintext pointer to the plaintext (uint8_t array)
 * @param plaintext_size pointer to the plaintext size (size_t)
 *
 */
void ecb_decrypt(const uint8_t *ciphertext, const size_t ciphertext_size, const uint8_t *password, uint8_t **plaintext, size_t *plaintext_size);

#endif