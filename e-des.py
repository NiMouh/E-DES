import unittest
import hashlib
import argparse
import sys

NUMBER_OF_ROUNDS = 16
NUMBER_OF_SBOXES = 16
BLOCK_SIZE = 8 # bytes
HALF_BLOCK_SIZE = 4 # bytes
S_BOX_SIZE = 256 # bytes
SHA_256_SIZE = 32 # bytes

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

    padded_data = bytearray(plaintext)

    for _ in range(number_of_padding_bytes):
        padded_data.append(number_of_padding_bytes)

    return padded_data

def remove_padding(padded_plaintext : bytearray) -> bytearray:
    padded_plaintext_size = len(padded_plaintext)

    last_byte = padded_plaintext[padded_plaintext_size - 1]
    number_of_padding_bytes = int(bytes([last_byte]).decode('utf-8'))

    plaintext = bytearray(padded_plaintext[:padded_plaintext_size - number_of_padding_bytes])

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
    parser.add_argument('-c', '--cipher', action='store_true', help='Cipher the input file')
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

class TestFeistelFunctions(unittest.TestCase):

    def test_feistel_function(self):
        input_block = bytearray([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])

        s_box = bytearray(
            [0x00, 0x00, 0x01, 0x01, 0x02, 0x02, 0x03, 0x03, 0x04, 0x04, 0x05, 0x05, 0x06, 0x06, 0x07, 0x07,
             0x08, 0x08, 0x09, 0x09, 0x0a, 0x0a, 0x0b, 0x0b, 0x0c, 0x0c, 0x0d, 0x0d, 0x0e, 0x0e, 0x0f, 0x0f,
             0x10, 0x10, 0x11, 0x11, 0x12, 0x12, 0x13, 0x13, 0x14, 0x14, 0x15, 0x15, 0x16, 0x16, 0x17, 0x17,
             0x18, 0x18, 0x19, 0x19, 0x1a, 0x1a, 0x1b, 0x1b, 0x1c, 0x1c, 0x1d, 0x1d, 0x1e, 0x1e, 0x1f, 0x1f,
             0x20, 0x20, 0x21, 0x21, 0x22, 0x22, 0x23, 0x23, 0x24, 0x24, 0x25, 0x25, 0x26, 0x26, 0x27, 0x27,
             0x28, 0x28, 0x29, 0x29, 0x2a, 0x2a, 0x2b, 0x2b, 0x2c, 0x2c, 0x2d, 0x2d, 0x2e, 0x2e, 0x2f, 0x2f,
             0x30, 0x30, 0x31, 0x31, 0x32, 0x32, 0x33, 0x33, 0x34, 0x34, 0x35, 0x35, 0x36, 0x36, 0x37, 0x37,
             0x38, 0x38, 0x39, 0x39, 0x3a, 0x3a, 0x3b, 0x3b, 0x3c, 0x3c, 0x3d, 0x3d, 0x3e, 0x3e, 0x3f, 0x3f,
             0x40, 0x40, 0x41, 0x41, 0x42, 0x42, 0x43, 0x43, 0x44, 0x44, 0x45, 0x45, 0x46, 0x46, 0x47, 0x47,
             0x48, 0x48, 0x49, 0x49, 0x4a, 0x4a, 0x4b, 0x4b, 0x4c, 0x4c, 0x4d, 0x4d, 0x4e, 0x4e, 0x4f, 0x4f,
             0x50, 0x50, 0x51, 0x51, 0x52, 0x52, 0x53, 0x53, 0x54, 0x54, 0x55, 0x55, 0x56, 0x56, 0x57, 0x57,
             0x58, 0x58, 0x59, 0x59, 0x5a, 0x5a, 0x5b, 0x5b, 0x5c, 0x5c, 0x5d, 0x5d, 0x5e, 0x5e, 0x5f, 0x5f,
             0x60, 0x60, 0x61, 0x61, 0x62, 0x62, 0x63, 0x63, 0x64, 0x64, 0x65, 0x65, 0x66, 0x66, 0x67, 0x67,
             0x68, 0x68, 0x69, 0x69, 0x6a, 0x6a, 0x6b, 0x6b, 0x6c, 0x6c, 0x6d, 0x6d, 0x6e, 0x6e, 0x6f, 0x6f,
             0x70, 0x70, 0x71, 0x71, 0x72, 0x72, 0x73, 0x73, 0x74, 0x74, 0x75, 0x75, 0x76, 0x76, 0x77, 0x77,
             0x78, 0x78, 0x79, 0x79, 0x7a, 0x7a, 0x7b, 0x7b, 0x7c, 0x7c, 0x7d, 0x7d, 0x7e, 0x7e, 0x7f, 0x7f])

        result = feistel_function(input_block, s_box)

        expected_result = ([0x00, 0x00, 0x00, 0x00])
        self.assertEqual(result, expected_result)