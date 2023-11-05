"""!
@file speed.py
@brief This file contains the functions used to measure the performance of the E-DES algorithm.
@author Ana Vidal (118408)
@author Simão Andrade (118345)
@date 2023-10-20
"""

import e_des
import time
from Crypto.Cipher import DES

def generate_random_data(number_of_bytes : int) -> bytearray:
    """!
    @brief This function generates random data.

    @param number_of_bytes The number of bytes to generate.

    @return The random data.
    """

    urandom_file = open('/dev/urandom', 'rb')
    random_data = urandom_file.read(number_of_bytes)
    urandom_file.close()

    return random_data

def speed_encrypt(number_of_tests : bytearray, number_of_bytes : int) -> None:
    """!
    This function measures the encryption time of DES-ECB and E-DES.

    @param number_of_tests The number of tests to run.
    @param number_of_bytes The number of bytes to encrypt.

    @return None
    """


    random_data = generate_random_data(number_of_bytes)
    password = generate_random_data(e_des.BLOCK_SIZE)

    # DES-ECB encryption time
    time_list_ecb = []
    for _ in range(number_of_tests):
        start_time = time.time_ns()
        cipher = DES.new(password, DES.MODE_ECB)
        cipher.encrypt(random_data)
        end_time = time.time_ns()

        time_list_ecb.append(end_time - start_time)
    
    # E-DES encryption time
    sboxes = e_des.generate_sboxes(password)

    time_list_e_des = []
    for _ in range(number_of_tests):
        start_time = time.time_ns()
        for block_index in range(0, number_of_bytes, e_des.BLOCK_SIZE):
            block = random_data[block_index:block_index + e_des.BLOCK_SIZE]
            block = e_des.feistel_network(block, sboxes)
        end_time = time.time_ns()

        time_list_e_des.append(end_time - start_time)

    print("Number of tests: {}".format(number_of_tests))
    print("Number of bytes: {}".format(number_of_bytes))

    print("DES-ECB encryption time (in nanoseconds):")
    print("Minimum: {}".format(min(time_list_ecb)))
    print("Maximum: {}".format(max(time_list_ecb)))
    print("Average: {}".format(sum(time_list_ecb) / len(time_list_ecb)))

    print("E-DES encryption time (in nanoseconds):")
    print("Minimum: {}".format(min(time_list_e_des)))
    print("Maximum: {}".format(max(time_list_e_des)))
    print("Average: {}".format(sum(time_list_e_des) / len(time_list_e_des)))


def speed_decrypt(number_of_tests : bytearray, number_of_bytes : int) -> None:
    """!
    @brief This function measures the decryption time of DES-ECB and E-DES.

    @param number_of_tests The number of tests to run.
    @param number_of_bytes The number of bytes to decrypt.

    @return None
    """

    random_data = generate_random_data(number_of_bytes)
    password = generate_random_data(e_des.BLOCK_SIZE)

    # DES-ECB decryption time
    time_list_ecb = []
    for _ in range(number_of_tests):
        cipher = DES.new(password, DES.MODE_ECB)
        ciphertext = cipher.encrypt(random_data)

        start_time = time.time_ns()
        cipher.decrypt(ciphertext)
        end_time = time.time_ns()

        time_list_ecb.append(end_time - start_time)

    # E-DES decryption time
    sboxes = e_des.generate_sboxes(password)

    time_list_e_des = []
    for _ in range(number_of_tests):
        ciphertext = e_des.encrypt(random_data, password)

        start_time = time.time_ns()
        for block_index in range(0, number_of_bytes, e_des.BLOCK_SIZE):
            block = ciphertext[block_index:block_index + e_des.BLOCK_SIZE]
            block = e_des.inverse_feistel_network(block, sboxes)
        end_time = time.time_ns()

        time_list_e_des.append(end_time - start_time)

    
    # Print results
    print("Number of tests: {}".format(number_of_tests))
    print("Number of bytes: {}".format(number_of_bytes))

    print("DES-ECB decryption time (in nanoseconds):")
    print("Minimum: {}".format(min(time_list_ecb)))
    print("Maximum: {}".format(max(time_list_ecb)))
    print("Average: {}".format(sum(time_list_ecb) / len(time_list_ecb)))

    print("E-DES decryption time (in nanoseconds):")
    print("Minimum: {}".format(min(time_list_e_des)))
    print("Maximum: {}".format(max(time_list_e_des)))
    print("Average: {}".format(sum(time_list_e_des) / len(time_list_e_des)))

if __name__ == "__main__":

    speed_encrypt(e_des.NUMBER_OF_RUNS, e_des.BUFFER_SIZE)
    speed_decrypt(e_des.NUMBER_OF_RUNS, e_des.BUFFER_SIZE)