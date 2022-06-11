from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC
from Cryptodome.Hash import SHA256
from key_and_padding import key_generator
from key_and_padding import padding
from key_and_padding import unpadding


# -------------------------------------------  ETM --> Encrypt-then-MAC  ----------------------------------------------


def ETM_encrypt(message):

    cipher_key = key_generator()
    hmac_key = key_generator()
    padded_msg = padding(message)

    cipher = AES.new(cipher_key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(padded_msg)

    # iv + texto cifrado --> alterações no iv poderiam permitir decriptar mesmo com uma tag inválida --> Hash(texto cifrado) = tag
    hmac = HMAC.new(hmac_key, cipher.iv + cipher_text, SHA256)
    tag = hmac.digest()

    return cipher.iv + tag + cipher_text, cipher_key, hmac_key


def ETM_decrypt(info, cipher_key, hmac_key):

    iv = info[:16]
    tag = info[16:48]
    cipher_text = info[48:]

    hmac = HMAC.new(hmac_key, iv + cipher_text, SHA256)

    try:
        hmac.verify(tag)
    except ValueError:
        print("Falha na verificação da tag!")
        return

    cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    message = cipher.decrypt(cipher_text)

    return unpadding(message)


# ----------------------------------------  EAM --> Encrypt-and-MAC  --------------------------------------------------


def EAM_encrypt(message):

    key = key_generator()
    padded_msg = padding(message)

    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(padded_msg)

    hmac = HMAC.new(key, padded_msg, SHA256)
    tag = hmac.digest()

    return cipher.iv + tag + cipher_text, key


def EAM_decrypt(info, key):

    iv = info[:16]
    tag = info[16:48]
    cipher_text = info[48:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = cipher.decrypt(cipher_text)

    hmac = HMAC.new(key, message, SHA256)               # Hash(mensagem com padding)
    try:
        hmac.verify(tag)
    except ValueError:
        print("Falha na verificação da tag!")
        return

    return unpadding(message)


# ----------------------------------------  MTE --> MAC-then-Encrypt  -------------------------------------------------


def MTE_encrypt(message):

    key = key_generator()
    padded_msg = padding(message)

    cipher = AES.new(key, AES.MODE_CBC)
    hmac = HMAC.new(key, padded_msg, SHA256)

    tag = hmac.digest()
    cipher_text = cipher.encrypt(tag + padded_msg)      # texto cifrado = E(chave, tag + mensagem)

    return cipher.iv + cipher_text, key, tag


def MTE_decrypt(info, key):

    iv = info[:16]
    cipher_text = info[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    tag_msg = cipher.decrypt(cipher_text)

    tag = tag_msg[:32]
    message = tag_msg[32:]

    hmac = HMAC.new(key, message, SHA256)               # Hash(mensagem com padding)
    try:
        hmac.verify(tag)
    except ValueError:
        print("Falha na verificação da tag!")
        return

    return unpadding(message)
