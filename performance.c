#include "implementation.h"

/**
 * Function that generates random data using '/dev/urandom' and stores it in a buffer
 * 
 * @param buffer pointer to the buffer (uint8_t array)
 * @param buffer_size the buffer size (size_t)
 */
void generate_random_data(uint8_t *buffer, size_t buffer_size){
    FILE *urandom = fopen("/dev/urandom", "rb");

    if (urandom == NULL) // Check for errors
    {
        printf("Error opening /dev/urandom\n");
        exit(1);
    }

    fread(buffer, sizeof(uint8_t), buffer_size, urandom);

    fclose(urandom);
}

/**
 * Function that tests the speed of the encryption and decryption functions (ECB and E-DES implementations)
 * 
 * @param number_of_tests number of tests to run (int)
 * @param number_of_bytes number of bytes to encrypt/decrypt (size_t)
 */
void speed(const int number_of_tests, const size_t number_of_bytes){
    // Generate the random bytes
    uint8_t *random_bytes = (uint8_t *)malloc(sizeof(uint8_t) * number_of_bytes);

    if (random_bytes == NULL) // memory allocation error
    {
        printf("Error allocating memory for random bytes\n");
        exit(1);
    }

    generate_random_data(random_bytes, number_of_bytes);

    // Generate the password
    uint8_t *password = (uint8_t *)malloc(sizeof(uint8_t) * BLOCK_SIZE);

    if (password == NULL) // memory allocation error
    {
        printf("Error allocating memory for password\n");
        exit(1);
    }

    // Encrypt for E-DES
    uint8_t *ciphertext;
    size_t ciphertext_size;

    // Declaration of variables for the performance measurement
    double maximum_achievable_speed_seconds = 0.0;
    double minimum_achievable_speed_seconds = 0.0;
    double average_achievable_speed_seconds = 0.0;
    double total_time_seconds = 0.0;

    // Declaration of variables for the time measurement
    clock_t start, end;
    clock_t start_each, end_each;

    // Time array
    double *times = (double *)malloc(sizeof(double) * number_of_tests);

    if (times == NULL) // memory allocation error
    {
        printf("Error allocating memory for times\n");
        exit(1);
    }

    // Encrypt
    start = clock();

    for (int test_index = 0; test_index < number_of_tests; test_index++)
    {
        // Generate the password
        generate_random_data(password, BLOCK_SIZE);

        // Encrypt
        start_each = clock();
        encrypt(random_bytes, password, &ciphertext, &ciphertext_size);
        end_each = clock();

        // Calculate the time
        times[test_index] = ((double)(end_each - start_each)) / CLOCKS_PER_SEC;

        free(ciphertext);
        free(password);
    }

    end = clock();

    // Calculate the time
    total_time_seconds = ((double)(end - start)) / CLOCKS_PER_SEC;
    average_achievable_speed_seconds = total_time_seconds / number_of_tests;

    // Calculate the maximum and minimum achievable speed
    for (int test_index = 0; test_index < number_of_tests; test_index++)
    {
        if (times[test_index] > maximum_achievable_speed_seconds)
        {
            maximum_achievable_speed_seconds = times[test_index];
        }

        if (times[test_index] < minimum_achievable_speed_seconds)
        {
            minimum_achievable_speed_seconds = times[test_index];
        }
    }

    free(times);

    printf("Tests for encryption on E-DES are completed!!\n");


    // Encrypt for ECB
    uint8_t *ciphertext_ecb;
    size_t ciphertext_size_ecb;

    // Declaration of variables for the performance measurement
    double maximum_achievable_speed_seconds_ecb = 0.0;
    double minimum_achievable_speed_seconds_ecb = 0.0;
    double average_achievable_speed_seconds_ecb = 0.0;
    double total_time_seconds_ecb = 0.0;

    // Time array
    double *times_ecb = (double *)malloc(sizeof(double) * number_of_tests);

    if (times_ecb == NULL) // memory allocation error
    {
        printf("Error allocating memory for times_ecb\n");
        exit(1);
    }

    // Encrypt
    start = clock();

    for (int test_index = 0; test_index < number_of_tests; test_index++)
    {
        // Generate the password
        generate_random_data(password, BLOCK_SIZE);

        // Encrypt
        start_each = clock();
        ecb_encrypt(random_bytes, password, &ciphertext_ecb);
        end_each = clock();

        // Calculate the time
        times_ecb[test_index] = ((double)(end_each - start_each)) / CLOCKS_PER_SEC;

        free(ciphertext_ecb);
        free(password);
    }

    end = clock();

    // Calculate the time
    total_time_seconds_ecb = ((double)(end - start)) / CLOCKS_PER_SEC;
    average_achievable_speed_seconds_ecb = total_time_seconds_ecb / number_of_tests;

    // Calculate the maximum and minimum achievable speed
    for (int test_index = 0; test_index < number_of_tests; test_index++)
    {
        if (times_ecb[test_index] > maximum_achievable_speed_seconds_ecb)
        {
            maximum_achievable_speed_seconds_ecb = times_ecb[test_index];
        }

        if (times_ecb[test_index] < minimum_achievable_speed_seconds_ecb)
        {
            minimum_achievable_speed_seconds_ecb = times_ecb[test_index];
        }
    }

    free(times_ecb);

    printf("Tests for encryption on ECB are completed!!\n");


    // Decrypt for E-DES
    uint8_t *plaintext;
    size_t plaintext_size;

    // Declaration of variables for the performance measurement
    double maximum_achievable_speed_seconds_decrypt = 0.0;
    double minimum_achievable_speed_seconds_decrypt = 0.0;
    double average_achievable_speed_seconds_decrypt = 0.0;
    double total_time_seconds_decrypt = 0.0;

    // Time array
    double *times_decrypt = (double *)malloc(sizeof(double) * number_of_tests);

    if (times_decrypt == NULL) // memory allocation error
    {
        printf("Error allocating memory for times_decrypt\n");
        exit(1);
    }

    // Decrypt
    start = clock();

    for (int test_index = 0; test_index < number_of_tests; test_index++)
    {
        // Generate the password
        generate_random_data(password, BLOCK_SIZE);

        // Decrypt
        start_each = clock();
        decrypt(random_bytes, number_of_bytes, password, &plaintext, &plaintext_size);
        end_each = clock();

        // Calculate the time
        times_decrypt[test_index] = ((double)(end_each - start_each)) / CLOCKS_PER_SEC;

        free(plaintext);
        free(password);
    }

    end = clock();

    // Calculate the time
    total_time_seconds_decrypt = ((double)(end - start)) / CLOCKS_PER_SEC;
    average_achievable_speed_seconds_decrypt = total_time_seconds_decrypt / number_of_tests;

    // Calculate the maximum and minimum achievable speed
    for (int test_index = 0; test_index < number_of_tests; test_index++)
    {
        if (times_decrypt[test_index] > maximum_achievable_speed_seconds_decrypt)
        {
            maximum_achievable_speed_seconds_decrypt = times_decrypt[test_index];
        }

        if (times_decrypt[test_index] < minimum_achievable_speed_seconds_decrypt)
        {
            minimum_achievable_speed_seconds_decrypt = times_decrypt[test_index];
        }
    }

    free(times_decrypt);

    printf("Tests for decryption on E-DES are completed!!\n");


    // Decrypt for ECB
    uint8_t *plaintext_ecb;
    size_t plaintext_size_ecb;

    // Declaration of variables for the performance measurement
    double maximum_achievable_speed_seconds_decrypt_ecb = 0.0;
    double minimum_achievable_speed_seconds_decrypt_ecb = 0.0;
    double average_achievable_speed_seconds_decrypt_ecb = 0.0;
    double total_time_seconds_decrypt_ecb = 0.0;

    // Time array
    double *times_decrypt_ecb = (double *)malloc(sizeof(double) * number_of_tests);

    if (times_decrypt_ecb == NULL) // memory allocation error
    {
        printf("Error allocating memory for times_decrypt_ecb\n");
        exit(1);
    }

    // Decrypt
    start = clock();

    for (int test_index = 0; test_index < number_of_tests; test_index++)
    {
        // Generate the password
        generate_random_data(password, BLOCK_SIZE);

        // Decrypt
        start_each = clock();
        ecb_decrypt(random_bytes, number_of_bytes, password, &plaintext_ecb);
        end_each = clock();

        // Calculate the time
        times_decrypt_ecb[test_index] = ((double)(end_each - start_each)) / CLOCKS_PER_SEC;

        free(plaintext_ecb);
        free(password);
    }

    end = clock();

    // Calculate the time
    total_time_seconds_decrypt_ecb = ((double)(end - start)) / CLOCKS_PER_SEC;
    average_achievable_speed_seconds_decrypt_ecb = total_time_seconds_decrypt_ecb / number_of_tests;

    // Calculate the maximum and minimum achievable speed
    for (int test_index = 0; test_index < number_of_tests; test_index++)
    {
        if (times_decrypt_ecb[test_index] > maximum_achievable_speed_seconds_decrypt_ecb)
        {
            maximum_achievable_speed_seconds_decrypt_ecb = times_decrypt_ecb[test_index];
        }

        if (times_decrypt_ecb[test_index] < minimum_achievable_speed_seconds_decrypt_ecb)
        {
            minimum_achievable_speed_seconds_decrypt_ecb = times_decrypt_ecb[test_index];
        }
    }

    free(times_decrypt_ecb);

    printf("Tests for decryption on ECB are completed!!\n");

    // Print the results
    printf("FINAL RESULTS:\n\n");
    printf("E-DES Mode Encrypt\n");
    printf("Maximum achievable speed: %f seconds.\n", maximum_achievable_speed_seconds);
    printf("Minimum achievable speed: %f seconds.\n", minimum_achievable_speed_seconds);
    printf("Average achievable speed: %f seconds.\n", average_achievable_speed_seconds);
    printf("Total time: %f seconds.\n", total_time_seconds);
    printf("\n");
    printf("DES-ECB Mode Encrypt\n");
    printf("Maximum achievable speed: %f seconds.\n", maximum_achievable_speed_seconds_ecb);
    printf("Minimum achievable speed: %f seconds.\n", minimum_achievable_speed_seconds_ecb);
    printf("Average achievable speed : %f seconds.\n", average_achievable_speed_seconds_ecb);
    printf("Total time: %f seconds.\n", total_time_seconds_ecb);
    printf("\n");
    printf("E-DES Mode Decrypt\n");
    printf("Maximum achievable speed: %f seconds.\n", maximum_achievable_speed_seconds_decrypt);
    printf("Minimum achievable speed: %f seconds.\n", minimum_achievable_speed_seconds_decrypt);
    printf("Average achievable speed: %f seconds.\n", average_achievable_speed_seconds_decrypt);
    printf("Total time: %f\n", total_time_seconds_decrypt);
    printf("\n");
    printf("DES-ECB Mode Decrypt\n");
    printf("Maximum achievable speed: %f seconds.\n", maximum_achievable_speed_seconds_decrypt_ecb);
    printf("Minimum achievable speed: %f seconds.\n", minimum_achievable_speed_seconds_decrypt_ecb);
    printf("Average achievable speed: %f seconds.\n", average_achievable_speed_seconds_decrypt_ecb);
    printf("Total time: %f\n", total_time_seconds_decrypt_ecb);
    printf("\n");

    free(random_bytes);
}



int main(void){

    // Test the speed of the encryption and decryption functions (ECB and E-DES implementations)
    speed(NUMBER_OF_TESTS, BUFFER_SIZE);

    return 0;
}