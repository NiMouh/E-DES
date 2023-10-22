#include "implementation.h"

void read_bytes(uint8_t *readed_bytes, size_t *number_of_readed_bytes)
{
    uint8_t byte;
    *number_of_readed_bytes = 0;

    size_t IS_READED = 1;
    while (fread(&byte, sizeof(uint8_t), 1, stdin) == IS_READED)
    {
        readed_bytes[*number_of_readed_bytes] = byte;
        *number_of_readed_bytes = *number_of_readed_bytes + 1;
    }
}

void write_bytes(const uint8_t *bytes_to_write, const size_t number_of_bytes_to_write)
{
    for (size_t byte_writed = 0; byte_writed < number_of_bytes_to_write; byte_writed++)
    {
        fwrite(&bytes_to_write[byte_writed], sizeof(uint8_t), 1, stdout);
    }
}

uint8_t *feistel_function(const uint8_t *input_block, const uint8_t *s_box)
{
    uint8_t *output_block = malloc(HALF_BLOCK_SIZE);

    uint8_t index = input_block[3];
    output_block[0] = s_box[index];

    index = index + input_block[2];
    output_block[1] = s_box[index];

    index = index + input_block[1];
    output_block[2] = s_box[index];

    index = index + input_block[0];
    output_block[3] = s_box[index];

    return output_block;
}

void feistel_network(const uint8_t *block, const struct s_box *sboxes, uint8_t **cipher_block)
{
    uint8_t *L = (uint8_t *)malloc(HALF_BLOCK_SIZE);
    uint8_t *R = (uint8_t *)malloc(HALF_BLOCK_SIZE);

    if (L == NULL || R == NULL) // memory allocation error
    {
        printf("Error allocating memory for L and/or R.\n");
        exit(1);
    }

    // Split the block in two halfs (L and R)
    memcpy(L, block, HALF_BLOCK_SIZE);
    memcpy(R, block + HALF_BLOCK_SIZE, HALF_BLOCK_SIZE);

    uint8_t *M = (uint8_t *)malloc(HALF_BLOCK_SIZE);
    for (int round = 0; round < NUMBER_OF_ROUNDS; round++)
    {
        // Copy the right to a temporary variable
        memcpy(M, R, HALF_BLOCK_SIZE);

        // Apply the feistel function to the right half
        uint8_t *feistel_result = feistel_function(R, sboxes[round].sbox);

        for (int index = 0; index < HALF_BLOCK_SIZE; index++)
        {
            R[index] = L[index] ^ feistel_result[index];
        }

        memcpy(L, M, HALF_BLOCK_SIZE);
    }

    // Concatenate the left and right halfs
    memcpy(*cipher_block, L, HALF_BLOCK_SIZE);
    memcpy(*cipher_block + HALF_BLOCK_SIZE, R, HALF_BLOCK_SIZE);
}

void inverse_feistel_network(const uint8_t *block, const struct s_box *sboxes, uint8_t **cipher_block)
{
    uint8_t *L = malloc(HALF_BLOCK_SIZE);
    uint8_t *R = malloc(HALF_BLOCK_SIZE);

    if (L == NULL || R == NULL) // memory allocation error
    {
        printf("Error allocating memory for L and/or R.\n");
        exit(1);
    }

    // Split the block in two halfs (L and R)
    memcpy(L, block, HALF_BLOCK_SIZE);
    memcpy(R, block + HALF_BLOCK_SIZE, HALF_BLOCK_SIZE);

    uint8_t *M = malloc(HALF_BLOCK_SIZE);
    for (int round = NUMBER_OF_ROUNDS - 1; round >= 0; round--)
    {
        // Copy the left to a temporary variable
        memcpy(M, L, HALF_BLOCK_SIZE);

        // Apply the inverse Feistel function to the right half
        uint8_t *feistel_result = feistel_function(L, sboxes[round].sbox);

        for (int index = 0; index < HALF_BLOCK_SIZE; index++)
        {
            L[index] = R[index] ^ feistel_result[index];
        }

        memcpy(R, M, HALF_BLOCK_SIZE);
    }

    // Concatenate the left and right halfs
    memcpy(*cipher_block, L, HALF_BLOCK_SIZE);
    memcpy(*cipher_block + HALF_BLOCK_SIZE, R, HALF_BLOCK_SIZE);
}

void generate_key(const uint8_t *password, uint8_t **key)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password, strlen((char *)password));
    SHA256_Final(*key, &ctx);
}

void generate_random_bytes(const uint8_t *key, uint8_t *bytes, int num_bytes)
{
    // Initialize the pseudo-random number generator with the key
    srand(*(unsigned int *)key);

    // Initialize an array to keep track of how many times each byte has been used
    int byteCount[256] = {0};

    for (int index = 0; index < num_bytes; index++)
    {
        // Find a byte value that has not been used 16 times
        uint8_t randomByte;
        do
        {
            randomByte = rand() & 0xFF; // Generate a random byte
        } while (byteCount[randomByte] >= NUMBER_OF_S_BOXES);

        bytes[index] = randomByte;
        byteCount[randomByte]++;
    }
}

void generate_sboxes(const uint8_t *key, struct s_box *sboxes)
{
    if (key != NULL)
    {
        // Generate the random bytes
        uint8_t *random_bytes = malloc(S_BOX_SIZE * NUMBER_OF_ROUNDS);
        generate_random_bytes(key, random_bytes, S_BOX_SIZE * NUMBER_OF_ROUNDS);

        // Copy the random bytes to the sboxes
        for (int sbox_index = 0; sbox_index < NUMBER_OF_ROUNDS; sbox_index++)
        {
            for (int item_index = 0; item_index < S_BOX_SIZE; item_index++)
            {
                sboxes[sbox_index].sbox[item_index] = random_bytes[sbox_index * S_BOX_SIZE + item_index];
            }
        }

        free(random_bytes);
    }
}

void add_padding(const uint8_t *plaintext, size_t plaintext_length, uint8_t **padded_plaintext, size_t *padded_length)
{
    // Calculate the new padded length
    size_t padding_bytes = BLOCK_SIZE - (plaintext_length % BLOCK_SIZE);
    *padded_length = plaintext_length + padding_bytes;

    // Allocate memory for padded_plaintext
    *padded_plaintext = (uint8_t *)malloc(*padded_length);

    if (*padded_plaintext == NULL)
    { // memory allocation error
        fprintf(stderr, "Error allocating memory for padded plaintext\n");
        exit(1);
    }

    // Copy the original plaintext
    memcpy(*padded_plaintext, plaintext, plaintext_length);

    // Add padding before the null terminator
    for (size_t i = plaintext_length; i < *padded_length; i++)
    {
        (*padded_plaintext)[i] = padding_bytes + '0';
    }
}

void remove_padding(const uint8_t *padded_plaintext, size_t padded_length, uint8_t **plaintext, size_t *plaintext_length)
{
    size_t padding_bytes = padded_plaintext[padded_length - 1] - '0';
    *plaintext_length = padded_length - padding_bytes;

    *plaintext = (uint8_t *)malloc(*plaintext_length);

    if (*plaintext == NULL) // memory allocation error
    {
        fprintf(stderr, "Error allocating memory for plaintext\n");
        exit(1);
    }

    // Copy the original plaintext including the null terminator
    memcpy(*plaintext, padded_plaintext, *plaintext_length);
}
