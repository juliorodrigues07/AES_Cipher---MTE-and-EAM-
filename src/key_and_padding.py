from Cryptodome.Random import get_random_bytes


def key_generator():

    key = get_random_bytes(16)
    return key


def padding(message):

    message += b'\x01'

    while len(message) % 16 != 0:
        message += b'\x00'

    return message


def unpadding(message):

    i = len(message) - 1

    while message[i] != 1:
        i = i - 1

    return message[:i]
