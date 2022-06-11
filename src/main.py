from autentication_ED import EAM_encrypt, EAM_decrypt
from autentication_ED import MTE_encrypt, MTE_decrypt
from autentication_ED import ETM_encrypt, ETM_decrypt


def main():

    # ------------------------------------------  Encrypt-and-MAC  ---------------------------------------------------

    message = b'Introducao a Criptografia'
    print("\nEncrypt-and-MAC:\n")
    print("Mensagem original:   ", message)

    info, key = EAM_encrypt(message)
    print("\nENCRIPTAÇÃO")
    print("Vetor inicialização: ", info[:16])
    print("Tag:                 ", info[16:48])
    print("Texto cifrado:       ", info[48:])
    print("Chave secreta:       ", key)

    decrypted_message = EAM_decrypt(info, key)
    print("\nDECRIPTAÇÃO")
    print("Mensagem decriptada: ", decrypted_message)

    # ------------------------------------------  MAC-then-Encrypt  ---------------------------------------------------

    message = b'Universidade Federal de Sao Joao Del Rei'
    print("\n\nMAC-then-Encrypt \n")
    print("Mensagem original:   ", message)

    info, key, tag = MTE_encrypt(message)
    print("\nENCRIPTAÇÃO")
    print("Vetor inicialização: ", info[:16])
    print("Texto Cifrado:       ", info[16:])
    print("Tag:                 ", tag)
    print("Chave Secreta:       ", key)

    decrypted_message = MTE_decrypt(info, key)
    print("\nDECRIPTAÇÃO")
    print("Mensagem decriptada: ", decrypted_message)

    # ------------------------------------------  Encrypt-then-MAC  ---------------------------------------------------

    message = b'Ciencia da Computacao'
    print("\n\nEncrypt-then-MAC \n")
    print("Mensagem original:   ", message)

    info, cipher_key, hmac_key = ETM_encrypt(message)
    print("\nENCRIPTAÇÃO")
    print("Vetor Inicialização: ", info[:16])
    print("Tag:                 ", info[16:48])
    print("Texto Cifrado:       ", info[48:])
    print("Chave secreta(cifra):", cipher_key)
    print("Chave secreta(HMAC): ", hmac_key)

    decrypted_message = ETM_decrypt(info, cipher_key, hmac_key)
    print("\nDECRIPTAÇÃO")
    print("Mensagem decriptada: ", decrypted_message)


if __name__ == '__main__':
    main()


