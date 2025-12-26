import os
import sys
from hashlib import sha1
from struct import pack, unpack
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


CHECK = bytes.fromhex('c43d7b00400700000000000000000000')  # 16 байт

def rar3_kdf(password: str, salt: bytes) -> tuple[bytes, bytes]:
    #KDF
    pwd = password.encode('utf-16le')
    seed = pwd + salt
    iv = b''
    h = sha1()
    for i in range(16):
        for j in range(0x4000):
            counter = pack('<L', i * 0x4000 + j)[:3]
            h.update(seed + counter)
            if j == 0:
                iv += h.digest()[19:20]
    key_be = h.digest()[:16]
    key = pack('<LLLL', *unpack('>LLLL', key_be))
    return key, iv

def encrypt_file(input_path: str, password: str, output_path: str = None):
    if output_path is None:
        output_path = input_path + '.rar'

    data = open(input_path, 'rb').read()

    salt = os.urandom(8)
    key, iv = rar3_kdf(password, salt)

    # Добавляем известный паттерн в начало — он будет использоваться для проверки
    data_with_check = CHECK + data

    # PKCS7 padding
    padded_data = pad(data_with_check, 16)

    # Шифрование AES-128-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded_data)

    # Формат файла: только salt (8 байт) + зашифрованные данные
    with open(output_path, 'wb') as f:
        f.write(salt)
        f.write(encrypted)

    print(f"Выходной файл: {output_path}")
    print(f"Пароль: {password}")
    print(f"Проверка пароля будет только по расшифровке и паттерну {CHECK.hex()}")

if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        print("Использование: python gen.py <файл> <пароль> [выходной_файл]")
        sys.exit(1)

    input_file = sys.argv[1]
    password = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) == 4 else None

    if not os.path.exists(input_file):
        print(f"Файл не найден: {input_file}")
        sys.exit(1)

    encrypt_file(input_file, password, output_file)