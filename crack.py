import sys
import itertools
import time
from hashlib import sha1
from struct import pack, unpack
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from concurrent.futures import ThreadPoolExecutor, as_completed
import os


CHECK = bytes.fromhex('c43d7b00400700000000000000000000')

def rar3_kdf(password: str, salt: bytes) -> tuple[bytes, bytes]:
    pwd = password.encode('utf-16le')
    seed = pwd + salt
    iv = b''
    h = sha1()
    for i in range(16):
        for j in range(16384):
            counter = pack('<L', i * 16384 + j)[:3]
            h.update(seed + counter)
            if j == 0:
                iv += h.digest()[19:20]
    key_be = h.digest()[:16]
    key = pack('<LLLL', *unpack('>LLLL', key_be))
    return key, iv

CHARSETS = {
    'l': 'abcdefghijklmnopqrstuvwxyz',
    'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'd': '0123456789',
}

def generate_passwords(mask: str):
    #Генератор всех паролей по маске
    parts = []
    for char in mask:
        if char in CHARSETS:
            parts.append(CHARSETS[char])
        else:
            parts.append(char)
    yield from itertools.product(*parts)

def password_to_str(pwd_tuple):
    return ''.join(pwd_tuple)

def verify_candidate(candidate: str, salt: bytes, encrypted_data: bytes) -> str | None:
    #Проверяет одного кандидата. Возвращает пароль, если найден, иначе None
    key, iv = rar3_kdf(candidate, salt)
    
    if len(encrypted_data) < 16:
        return None

    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        # Расшифровываем достаточно байт, чтобы захватить check
        to_decrypt = encrypted_data[:max(48, len(encrypted_data))]
        decrypted_padded = cipher.decrypt(to_decrypt)
        decrypted = unpad(decrypted_padded, 16)
        
        if decrypted.startswith(CHECK):
            return candidate
    except ValueError:
        pass  # Неверный padding или ключ
    return None

def crack_multithread(encrypted_file: str, mask: str, max_workers: int | None = None):
    with open(encrypted_file, 'rb') as f:
        salt = f.read(8)
        encrypted_data = f.read()

    if len(encrypted_data) == 0:
        print("Ошибка: зашифрованные данные пустые")
        return

    # Автоматически определяем количество потоков (ядер CPU)
    if max_workers is None:
        max_workers = os.cpu_count() 

    print(f"Запуск подбора пароля по маске: {mask}")
    print(f"Потоков: {max_workers} | Проверка по расшифровке и паттерну")
    print(f"Соль: {salt.hex()}")
    start_time = time.time()
    total_attempts = 0

    # Генерируем все пароли и разбиваем на батчи для потоков
    passwords_gen = generate_passwords(mask)
    batch_size = 1000  # сколько паролей обрабатывать за раз в одном потоке

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        batch = []

        for pwd_tuple in passwords_gen:
            candidate = password_to_str(pwd_tuple)
            batch.append(candidate)

            if len(batch) >= batch_size:
                # Отправляем батч в поток
                future = executor.submit(
                    lambda candidates, s=salt, ed=encrypted_data: [
                        verify_candidate(c, s, ed) for c in candidates
                    ],
                    batch.copy()
                )
                futures.append(future)
                batch.clear()
                total_attempts += batch_size

            # Прогресс
            if total_attempts % (batch_size * 10) == 0 and total_attempts > 0:
                elapsed = time.time() - start_time
                rate = total_attempts / elapsed if elapsed > 0 else 0
                print(f"Попыток: {total_attempts:,} | Время: {elapsed:.1f}с | Скорость: {rate:,.0f} пар/сек")

        # Остаток батча
        if batch:
            future = executor.submit(
                lambda candidates, s=salt, ed=encrypted_data: [
                    verify_candidate(c, s, ed) for c in candidates
                ],
                batch
            )
            futures.append(future)
            total_attempts += len(batch)

        # Проверяем результаты
        for future in as_completed(futures):
            results = future.result()
            for result in results:
                if result is not None:
                    elapsed = time.time() - start_time
                    rate = total_attempts / elapsed if elapsed > 0 else 0
                    print(f"\nПАРОЛЬ НАЙДЕН: {result}")
                    print(f"Всего попыток: {total_attempts:,}")
                    print(f"Время: {elapsed:.2f} секунд | Скорость: {rate:,.0f} пар/сек")
                    return result

    elapsed = time.time() - start_time
    rate = total_attempts / elapsed if elapsed > 0 else 0
    print(f"\nПароль не найден.")
    print(f"Всего попыток: {total_attempts:,} | Время: {elapsed:.2f}с | Скорость: {rate:,.0f} пар/сек")

if __name__ == "__main__":
    if len(sys.argv) not in [3, 4]:
        print("Использование:")
        print("  python crack.py <файл> <маска> [потоки]")
        print("Примеры:")
        print("  python crack.py file.rar lllldd")
        print("  python crack.py file.rar passddd 8")
        sys.exit(1)

    enc_file = sys.argv[1]
    mask = sys.argv[2]
    workers = int(sys.argv[3]) if len(sys.argv) == 4 else None

    crack_multithread(enc_file, mask, workers)