import unittest
import hashlib
import argparse
import sys

# For Implementation
NUMBER_OF_ROUNDS = 16
NUMBER_OF_SBOXES = 16
BLOCK_SIZE = 8 # bytes
HALF_BLOCK_SIZE = 4 # bytes
S_BOX_SIZE = 256 # bytes
SHA_256_SIZE = 32 # bytes

# For Performance Testing
NUMBER_OF_RUNS = 100000
BUFFER_SIZE = 4 * 1024 # 4 KiB

def feistel_function(input_block : bytearray, sbox : bytearray) -> bytearray:
    output_block = bytearray()

    index = input_block[3]
    output_block.append(sbox[index])

    index = (index + input_block[2]) % 256
    output_block.append(sbox[index])

    index = (index + input_block[1]) % 256
    output_block.append(sbox[index])

    index = (index + input_block[0]) % 256
    output_block.append(sbox[index])

    return output_block

def feistel_network(block : bytearray, sboxes : list) -> bytearray:

    L = bytearray(block[:HALF_BLOCK_SIZE])
    R = bytearray(block[HALF_BLOCK_SIZE:])

    for round in range(NUMBER_OF_ROUNDS):
        feistel_result = feistel_function(R, sboxes[round])

        for byte_index in range(HALF_BLOCK_SIZE):
            R[byte_index], L[byte_index] = L[byte_index] ^ feistel_result[byte_index], R[byte_index]
    
    return L + R

def inverse_feistel_network(block : bytearray, sboxes : list) -> bytearray:

    L = bytearray(block[:HALF_BLOCK_SIZE])
    R = bytearray(block[HALF_BLOCK_SIZE:])
    
    # For every round, from the last to the first
    for round in range(NUMBER_OF_ROUNDS - 1, -1, -1):

        feistel_result = feistel_function(L, sboxes[round])

        for byte_index in range(HALF_BLOCK_SIZE):
            L[byte_index], R[byte_index] = R[byte_index] ^ feistel_result[byte_index], L[byte_index]
        
    return L + R

def add_padding(plaintext : bytearray) -> bytearray:
    plaintext_size = len(plaintext)

    number_of_padding_bytes = BLOCK_SIZE - (plaintext_size % BLOCK_SIZE)

    padding_byte = number_of_padding_bytes.to_bytes(1, byteorder='big')
    padded_data = bytearray(plaintext + padding_byte * number_of_padding_bytes)

    return padded_data

def remove_padding(padded_plaintext: bytearray) -> bytearray:

    last_byte = bytes([padded_plaintext[-1]]).decode('utf-8')
    if not last_byte.isdigit():
        return padded_plaintext

    number_of_padding_bytes = int(last_byte)
    if number_of_padding_bytes > BLOCK_SIZE:
        return padded_plaintext

    plaintext = bytearray(padded_plaintext[:-number_of_padding_bytes])

    return plaintext

def generate_key(password : bytearray) -> bytearray:
    hash = hashlib.sha256()

    hash.update(password)

    key = hash.digest()

    return key

def generate_single_box(password : bytearray) -> bytearray:
    sbox = bytearray(range(S_BOX_SIZE))

    key = generate_key(password)

    for current_index in range(S_BOX_SIZE):
        new_index = (current_index + key[current_index % SHA_256_SIZE]) % S_BOX_SIZE
        sbox[current_index], sbox[new_index] = sbox[new_index], sbox[current_index]

    return sbox

def round_robin_shuffle(sboxes : list) -> list:
    new_sboxes = bytearray(0 for _ in range(len(sboxes)))
    size_of_sboxes = len(sboxes)

    shift = 1
    new_index = 0

    for sbox_index in range(size_of_sboxes):
        new_sboxes[new_index] = sboxes[sbox_index]
        new_index = (new_index + shift) % len(sboxes)

        shift += 1
        if shift >= len(sboxes):
            shift = 1
    
    return new_sboxes

def generate_sboxes(password : bytearray) -> list:

    single_sbox = generate_single_box(password)

    random_bytes = bytearray()
    for _ in range(NUMBER_OF_SBOXES):
        random_bytes.extend(single_sbox)

    random_bytes = round_robin_shuffle(random_bytes)

    sboxes = [bytearray(0 for _ in range(S_BOX_SIZE)) for _ in range(NUMBER_OF_SBOXES)]
    for sbox_index in range(NUMBER_OF_SBOXES):
        for item_index in range(S_BOX_SIZE):
            sboxes[sbox_index][item_index] = random_bytes[sbox_index * S_BOX_SIZE + item_index]
    
    return sboxes

def encrypt(plaintext : bytearray, password : bytearray) -> bytearray:

    ciphertext = bytearray()

    padded_plaintext = add_padding(plaintext)
    padded_plaintext_size = len(padded_plaintext)

    sboxes = generate_sboxes(password)

    for block_index in range(0, padded_plaintext_size, BLOCK_SIZE):

        block = padded_plaintext[block_index:block_index + BLOCK_SIZE]
        block = feistel_network(block, sboxes)

        ciphertext.extend(block)

    return ciphertext

def decrypt(ciphertext : bytearray, password : bytearray) -> bytearray:
    ciphertext_size = len(ciphertext)

    padded_plaintext = bytearray()

    sboxes = generate_sboxes(password)

    for block_index in range(0, ciphertext_size, BLOCK_SIZE):

        block = ciphertext[block_index:block_index + BLOCK_SIZE]
        block = inverse_feistel_network(block, sboxes)

        padded_plaintext.extend(block)
        
    plaintext = remove_padding(padded_plaintext)

    return plaintext

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file using the E-DES algorithm.')
    parser.add_argument('-e', '--cipher', action='store_true', help='Cipher the input file')
    parser.add_argument('-d', '--decipher', action='store_true', help='Decipher the input file')
    parser.add_argument('-p', '--password', required=True, help='Password used to encrypt/decrypt the file')
    arguments = parser.parse_args()

    password = bytearray(arguments.password, 'utf-8')

    if arguments.cipher:
        plaintext = sys.stdin.buffer.read()
        ciphertext = encrypt(plaintext, password)
        sys.stdout.buffer.write(ciphertext)
    elif arguments.decipher:
        ciphertext = sys.stdin.buffer.read()
        plaintext = decrypt(ciphertext, password)
        sys.stdout.buffer.write(plaintext)
    else:
        print('Please specify if you want to cipher or decipher the input file.')