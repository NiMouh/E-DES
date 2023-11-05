#include "implementation.h"

/**
 * @file speed.c
 * @brief Tests the performance of the encryption and decryption functions (ECB and E-DES implementations)
 *
 * @author Ana Vidal (118408)
 * @author Simão Andrade (118345)
 * @date 2023-10-20
 */


/**
 * Function that generates random data using '/dev/urandom' and stores it in a buffer
 * 
 * @param buffer pointer to the buffer (uint8_t array)
 * @param buffer_size the buffer size (size_t)
 */
void generate_random_data(uint8_t *buffer, size_t buffer_size)
{
    FILE *urandom = fopen("/dev/urandom", "r");
    fread(buffer, sizeof(uint8_t), buffer_size, urandom);
    fclose(urandom);
}

/**
 * Function that tests the speed of the encryption functions (ECB and E-DES implementations)
 * 
 * @param number_of_tests number of tests to run (int)
 * @param number_of_bytes number of bytes to encrypt/decrypt (size_t)
 */
void speed_encrypt(const int number_of_tests, const size_t number_of_bytes)
{

    // Time variables
    struct timespec start, end;

    // Generate the random bytes
    uint8_t random_bytes[number_of_bytes];
    generate_random_data(random_bytes, number_of_bytes);

    // Generate the password
    uint8_t password[BLOCK_SIZE];
    generate_random_data(password, BLOCK_SIZE);

    /* DES-ECB CIPHER */
    printf("DES-ECB CIPHER\n");

    // Generate the key schedule
    DES_key_schedule key_schedule;
    DES_set_key((DES_cblock*)password, &key_schedule);


    clock_t *time_list_ecb = (clock_t*)malloc(number_of_tests * sizeof(clock_t));
    for (int test = 0; test < number_of_tests; test++) {
        clock_t start_time = clock();
        // Perform DES-ECB encryption here
        for (int block_index = 0; block_index < number_of_bytes; block_index += BLOCK_SIZE)
        {
            // Perform DES-ECB encryption here
            DES_ecb_encrypt((DES_cblock *) (random_bytes + block_index), (DES_cblock *) (random_bytes + block_index), &key_schedule, DES_ENCRYPT);
        }
        clock_t end_time = clock();

        time_list_ecb[test] = end_time - start_time;
    }

    // Print the results (Min, Max, Average) in milliseconds
    clock_t minimum_time_ecb = time_list_ecb[0];
    clock_t maximum_time_ecb = time_list_ecb[0];
    clock_t total_time_ecb = 0;
    for (int test = 0; test < number_of_tests; test++) {
        if (time_list_ecb[test] < minimum_time_ecb) {
            minimum_time_ecb = time_list_ecb[test];
        }
        if (time_list_ecb[test] > maximum_time_ecb) {
            maximum_time_ecb = time_list_ecb[test];
        }
        total_time_ecb += time_list_ecb[test];
    }

    printf("Minium: %f ms\n", (double)minimum_time_ecb / (CLOCKS_PER_SEC / 1000));
    printf("Maximum: %f ms\n", (double)maximum_time_ecb / (CLOCKS_PER_SEC / 1000));
    printf("Average: %f ms\n", (double)total_time_ecb / (CLOCKS_PER_SEC / 1000) / number_of_tests);

    free(time_list_ecb);

    /* E-DES CIPHER */
    printf("E-DES CIPHER\n");

    struct s_box * sboxes = (struct s_box *)malloc(NUMBER_OF_S_BOXES * sizeof(struct s_box));

    if (sboxes == NULL) {
        printf("Error allocating memory for sboxes\n");
        exit(1);
    }

    generate_sboxes(password, sboxes);

    clock_t *time_list_edes = (clock_t*)malloc(number_of_tests * sizeof(clock_t));
    uint8_t *cipher_block = (uint8_t *)malloc(BLOCK_SIZE * sizeof(uint8_t));

    if (time_list_edes == NULL || cipher_block == NULL) {
        printf("Memory allocation error\n");
        exit(1);
    }

    for (int test = 0; test < number_of_tests; test++) {
        clock_t start_time = clock();
        for (int block_index = 0; block_index < number_of_bytes; block_index += BLOCK_SIZE)
        {
            // TODO: Add feistel_network(const uint8_t *block, const struct s_box *sboxes, uint8_t **cipher_block)
        }
        clock_t end_time = clock();

        time_list_edes[test] = end_time - start_time;
    }

    free(cipher_block);
    free(sboxes);

    // Print the results (Min, Max, Average) in milliseconds
    clock_t minimum_time_edes = time_list_edes[0];
    clock_t maximum_time_edes = time_list_edes[0];
    clock_t total_time_edes = 0;
    for (int test = 0; test < number_of_tests; test++) {
        if (time_list_edes[test] < minimum_time_edes) {
            minimum_time_edes = time_list_edes[test];
        }
        if (time_list_edes[test] > maximum_time_edes) {
            maximum_time_edes = time_list_edes[test];
        }
        total_time_edes += time_list_edes[test];
    }

    printf("Minium: %f ms\n", (double)minimum_time_edes / (CLOCKS_PER_SEC / 1000));
    printf("Maximum: %f ms\n", (double)maximum_time_edes / (CLOCKS_PER_SEC / 1000));
    printf("Average: %f ms\n", (double)total_time_edes / (CLOCKS_PER_SEC / 1000) / number_of_tests);
}

/**
 * Function that tests the speed of the decryption functions (ECB and E-DES implementations)
 * 
 * @param number_of_tests number of tests to run (int)
 * @param number_of_bytes number of bytes to encrypt/decrypt (size_t)
 */
void speed_decrypt(const int number_of_tests, const size_t number_of_bytes)
{
    // Time variables
    struct timespec start, end;

    // Generate the random bytes
    uint8_t random_bytes[number_of_bytes];
    generate_random_data(random_bytes, number_of_bytes);

    // Generate the password
    uint8_t password[BLOCK_SIZE];
    generate_random_data(password, BLOCK_SIZE);

    /* DES-ECB DECIPHER */
    printf("DES-ECB DECIPHER\n");

    // Generate the key schedule
    DES_key_schedule key_schedule;
    DES_set_key((DES_cblock*)password, &key_schedule);


    clock_t *time_list_ecb = (clock_t*)malloc(number_of_tests * sizeof(clock_t));
    for (int test = 0; test < number_of_tests; test++) {
        clock_t start_time = clock();
        // Perform DES-ECB encryption here
        for (int block_index = 0; block_index < number_of_bytes; block_index += BLOCK_SIZE)
        {
            // Perform DES-ECB encryption here
            DES_ecb_encrypt((DES_cblock *) (random_bytes + block_index), (DES_cblock *) (random_bytes + block_index), &key_schedule, DES_ENCRYPT);
        }
        clock_t end_time = clock();

        time_list_ecb[test] = end_time - start_time;
    }

    // Print the results (Min, Max, Average) in milliseconds
    clock_t minimum_time_ecb = time_list_ecb[0];
    clock_t maximum_time_ecb = time_list_ecb[0];
    clock_t total_time_ecb = 0;
    for (int test = 0; test < number_of_tests; test++) {
        if (time_list_ecb[test] < minimum_time_ecb) {
            minimum_time_ecb = time_list_ecb[test];
        }
        if (time_list_ecb[test] > maximum_time_ecb) {
            maximum_time_ecb = time_list_ecb[test];
        }
        total_time_ecb += time_list_ecb[test];
    }

    printf("Minium: %f ms\n", (double)minimum_time_ecb / (CLOCKS_PER_SEC / 1000));
    printf("Maximum: %f ms\n", (double)maximum_time_ecb / (CLOCKS_PER_SEC / 1000));
    printf("Average: %f ms\n", (double)total_time_ecb / (CLOCKS_PER_SEC / 1000) / number_of_tests);

    free(time_list_ecb);

    /* E-DES DECIPHER */
    printf("E-DES DECIPHER\n");

    struct s_box * sboxes = (struct s_box *)malloc(NUMBER_OF_S_BOXES * sizeof(struct s_box));

    if (sboxes == NULL) {
        printf("Error allocating memory for sboxes\n");
        exit(1);
    }

    generate_sboxes(password, sboxes);

    clock_t *time_list_edes = (clock_t*)malloc(number_of_tests * sizeof(clock_t));
    uint8_t *cipher_block = (uint8_t *)malloc(BLOCK_SIZE * sizeof(uint8_t));

    if (time_list_edes == NULL || cipher_block == NULL) {
        printf("Memory allocation error\n");
        exit(1);
    }

    for (int test = 0; test < number_of_tests; test++) {
        clock_t start_time = clock();
        for (int block_index = 0; block_index < number_of_bytes; block_index += BLOCK_SIZE)
        {
            // TODO: Add inverse_feistel_network(const uint8_t *block, const struct s_box *sboxes, uint8_t **cipher_block)
        }
        clock_t end_time = clock();

        time_list_edes[test] = end_time - start_time;
    }

    free(cipher_block);
    free(sboxes);

    // Print the results (Min, Max, Average) in milliseconds
    clock_t minimum_time_edes = time_list_edes[0];
    clock_t maximum_time_edes = time_list_edes[0];
    clock_t total_time_edes = 0;
    for (int test = 0; test < number_of_tests; test++) {
        if (time_list_edes[test] < minimum_time_edes) {
            minimum_time_edes = time_list_edes[test];
        }
        if (time_list_edes[test] > maximum_time_edes) {
            maximum_time_edes = time_list_edes[test];
        }
        total_time_edes += time_list_edes[test];
    }

    printf("Minium: %f ms\n", (double)minimum_time_edes / (CLOCKS_PER_SEC / 1000));
    printf("Maximum: %f ms\n", (double)maximum_time_edes / (CLOCKS_PER_SEC / 1000));
    printf("Average: %f ms\n", (double)total_time_edes / (CLOCKS_PER_SEC / 1000) / number_of_tests);
}



int main(void){
    speed_encrypt(NUMBER_OF_TESTS, BUFFER_SIZE); // TODO : FIX THIS FUNCTION

    // speed_decrypt(NUMBER_OF_TESTS, BUFFER_SIZE);

    return 0;
}