#include "implementation.h"

/**
 * Function that generates random data using '/dev/urandom' and stores it in a buffer
 * 
 * @param buffer pointer to the buffer (uint8_t array)
 * @param buffer_size the buffer size (size_t)
 */
void generate_random_data(uint8_t *buffer, size_t buffer_size) {
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) {
        perror("Failed to open /dev/urandom");
        exit(1); // Handle the error, possibly with an appropriate error message
    }

    size_t bytes_read = read(urandom_fd, buffer, buffer_size);
    if (bytes_read < 0) {
        perror("Failed to read from /dev/urandom");
        close(urandom_fd);
        exit(1); // Handle the error, possibly with an appropriate error message
    }

    close(urandom_fd);
}

/**
 * Function that tests the speed of the encryption functions (ECB and E-DES implementations)
 * 
 * @param number_of_tests number of tests to run (int)
 * @param number_of_bytes number of bytes to encrypt/decrypt (size_t)
 */
void speed_encrypt(const int number_of_tests, const size_t number_of_bytes){ // TODO : FIX THIS FUNCTION

    // Time variables
    struct timespec start, end;

    // Generate the random bytes
    uint8_t random_bytes[number_of_bytes];
    generate_random_data(random_bytes, number_of_bytes);

    // Generate the password
    const uint8_t *password = "password12345678";

    /* DES-ECB CIPHER */
    printf("DES-ECB CIPHER\n");

    // Generate the key schedule
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, password, BLOCK_SIZE);

    DES_set_odd_parity(&des_key);
    DES_set_key_checked(&des_key, &schedule);

    // Encrypt
    uint8_t des_ciphertext[number_of_bytes];
    size_t des_ciphertext_size = 0;

    // Store the times in an array
    uint64_t times_for_des[number_of_tests];

    for (size_t time_index = 0; time_index < number_of_tests; time_index++) // Testing encryption in DES-ECB
    {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);

        for (size_t block_index = 0; block_index < number_of_bytes; block_index+= BLOCK_SIZE)
        {
            DES_ecb_encrypt((DES_cblock *)(random_bytes + block_index * BLOCK_SIZE), (DES_cblock *)(des_ciphertext + block_index * BLOCK_SIZE), &schedule, DES_ENCRYPT);
        }

        clock_gettime(CLOCK_MONOTONIC_RAW, &end);

        times_for_des[time_index] = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);
    }

    // DES-ECB
    uint64_t min_time_des = times_for_des[0];
    uint64_t max_time_des = times_for_des[0];
    uint64_t sum_time_des = 0;

    for (size_t time_index = 0; time_index < number_of_tests; time_index++)
    {
        if (times_for_des[time_index] < min_time_des)
        {
            min_time_des = times_for_des[time_index];
        }

        if (times_for_des[time_index] > max_time_des)
        {
            max_time_des = times_for_des[time_index];
        }

        sum_time_des += times_for_des[time_index];
    }

    printf("DES-ECB: Minimum time: %lu ns\n", min_time_des);
    printf("DES-ECB: Maximum time: %lu ns\n", max_time_des);
    printf("DES-ECB: Average time: %lu ns\n", sum_time_des / number_of_tests);

    /* E-DES CIPHER */
    printf("E-DES CIPHER\n");

    // Generate the sboxes
    struct s_box sboxes[NUMBER_OF_S_BOXES];
    generate_sboxes(password, sboxes);

    // Encrypt
    uint8_t ciphertext[number_of_bytes];
    size_t ciphertext_size = 0;

    // Store the times in an array
    uint64_t times_for_edes[number_of_tests];

    for (size_t time_index = 0; time_index < number_of_tests; time_index++) // Testing encryption in E-DES
    {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);

        for (size_t block_index = 0; block_index < number_of_bytes; block_index+= BLOCK_SIZE)
        {
            uint8_t *cipher_block = malloc(BLOCK_SIZE * sizeof(uint8_t));
            feistel_network(random_bytes + block_index, sboxes, &cipher_block);
    
            // Store the cipher block in the ciphertext
            for (size_t byte_index = 0; byte_index < BLOCK_SIZE; byte_index++)
            {
                ciphertext[block_index + byte_index] = cipher_block[byte_index];
            }

            free(cipher_block);
        }

        clock_gettime(CLOCK_MONOTONIC_RAW, &end);

        times_for_edes[time_index] = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);
    }

    uint64_t min_time_edes = times_for_edes[0];
    uint64_t max_time_edes = times_for_edes[0];
    uint64_t sum_time_edes = 0;

    for (size_t time_index = 0; time_index < number_of_tests; time_index++)
    {
        if (times_for_edes[time_index] < min_time_edes)
        {
            min_time_edes = times_for_edes[time_index];
        }

        if (times_for_edes[time_index] > max_time_edes)
        {
            max_time_edes = times_for_edes[time_index];
        }

        sum_time_edes += times_for_edes[time_index];
    }

    printf("E-DES: Minimum time: %lu ns\n", min_time_edes);
    printf("E-DES: Maximum time: %lu ns\n", max_time_edes);
    printf("E-DES: Average time: %lu ns\n", sum_time_edes / number_of_tests);
}

/**
 * Function that tests the speed of the decryption functions (ECB and E-DES implementations)
 * 
 * @param number_of_tests number of tests to run (int)
 * @param number_of_bytes number of bytes to encrypt/decrypt (size_t)
 */
void speed_decrypt(const int number_of_tests, const size_t number_of_bytes){
    // TODO : Implement this function
}



int main(void){

    // Test the speed of the encryption functions (ECB and E-DES implementations)
    speed_encrypt(NUMBER_OF_TESTS, BUFFER_SIZE);

    return 0;
}