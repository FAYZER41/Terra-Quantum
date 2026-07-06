import hashlib
import os
from typing import Optional, Dict, Tuple

class TerraQuantum_v2_1:
    """
    Терра-Квант v2.1 — Пост-квантовый поточный шифр.
    """

    def __init__(self, key: bytes, nonce: int = 0):
        self.Q = 2**256 - 39
        self.P = 2**255 - 19
        self.CONST = 0x9E3779B97F4A7C159E3779B97F4A7C159E3779B97F4A7C159E3779B97F4A7C15
        self.rounds = 0

        seed = hashlib.sha3_512(key).digest() + hashlib.shake_256(key).digest(64)
        self.A = int.from_bytes(seed[0:32], 'little')
        self.B = int.from_bytes(seed[32:64], 'little')
        self.C = int.from_bytes(seed[64:96], 'little')
        self.D = int.from_bytes(seed[96:128], 'little')

        self.nonce = nonce
        self.sbox = self._generate_sbox()

    def _generate_sbox(self) -> list:
        shake = hashlib.shake_256()
        shake.update((self.A & ((1 << 256) - 1)).to_bytes(32, 'little'))
        shake.update((self.B & ((1 << 256) - 1)).to_bytes(32, 'little'))
        shake.update((self.C & ((1 << 256) - 1)).to_bytes(32, 'little'))
        shake.update((self.D & ((1 << 256) - 1)).to_bytes(32, 'little'))
        shake.update(self.nonce.to_bytes(8, 'little'))

        sbox = list(range(256))
        for i in range(255, 0, -1):
            j = shake.digest(1)[0] % (i + 1)
            sbox[i], sbox[j] = sbox[j], sbox[i]
        return sbox

    def _rotl(self, x: int, n: int) -> int:
        n %= 256
        return ((x << n) | (x >> (256 - n))) & ((1 << 256) - 1)

    def _rotr(self, x: int, n: int) -> int:
        n %= 256
        return ((x >> n) | (x << (256 - n))) & ((1 << 256) - 1)

    def _gf256_mul(self, a: int, b: int) -> int:
        result = 0
        for _ in range(256):
            if b & 1:
                result ^= a
            carry = a & (1 << 255)
            a = (a << 1) & ((1 << 256) - 1)
            if carry:
                a ^= 0x425
            b >>= 1
        return result

    def _mod_inv(self, x: int, p: int) -> int:
        return 0 if x == 0 else pow(x, -1, p)

    def next_byte(self) -> int:
        A_new = (self.A + self._rotl(self.B, 13) ^ self._rotr(self.C, 7) + self.D) % self.Q

        num = (self.B**2 + self.C**2) % self.P
        den = (1 + self.D**2 * self.B**2) % self.P
        B_new = (num * self._mod_inv(den, self.P)) % self.P

        idx = (self.A ^ self.B) & 0xFF
        C_new = self.sbox[idx] ^ self._rotl(self.C, 61) ^ self._rotr(self.C, 3) ^ self.CONST
        C_new &= ((1 << 256) - 1)

        c_limited = self.C & ((1 << 256) - 1)
        d_limited = self.D & ((1 << 256) - 1)
        inp = c_limited.to_bytes(32, 'little') + d_limited.to_bytes(32, 'little') + self.nonce.to_bytes(8, 'little')
        D_new = self._gf256_mul(self.A, self.B) ^ int.from_bytes(hashlib.sha3_512(inp).digest(), 'little')

        out_byte = self.sbox[(C_new >> 248) & 0xFF] ^ ((B_new >> 240) & 0xFF)

        self.A = A_new ^ self._rotr(B_new ^ (self.sbox[B_new & 0xFF] << 8), 64)
        self.B = B_new ^ self._rotl(C_new ^ (self.sbox[(C_new >> 8) & 0xFF] << 16), 32)
        self.C = C_new ^ self._rotr(D_new, 16)
        self.D = D_new ^ self._rotl(A_new, 48)

        self.rounds += 1
        if self.rounds % 1_000_000 == 0:
            self.nonce += 1
            self.sbox = self._generate_sbox()

        return out_byte & 0xFF

    def generate_stream(self, length: int) -> bytes:
        return bytes([self.next_byte() for _ in range(length)])

    def encrypt(self, plaintext: bytes) -> bytes:
        stream = self.generate_stream(len(plaintext))
        return bytes([p ^ s for p, s in zip(plaintext, stream)])

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)

    @staticmethod
    def generate_key(size: int = 32) -> bytes:
        return os.urandom(size)

    @staticmethod
    def derive_key(password: str, salt: Optional[bytes] = None, iterations: int = 1_000_000) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha3_512', password.encode(), salt, iterations, dklen=32)
        return key, salt

    def encrypt_with_ad(self, plaintext: bytes, ad: bytes = b'') -> bytes:
        if ad:
            h = hashlib.shake_256(ad).digest(8)
            self.nonce = self.nonce ^ int.from_bytes(h, 'little')
            self.sbox = self._generate_sbox()
        return self.encrypt(plaintext)

    def decrypt_with_ad(self, ciphertext: bytes, ad: bytes = b'') -> bytes:
        if ad:
            h = hashlib.shake_256(ad).digest(8)
            self.nonce = self.nonce ^ int.from_bytes(h, 'little')
            self.sbox = self._generate_sbox()
        return self.decrypt(ciphertext)

    def export_state(self) -> Dict:
        return {
            'A': self.A.to_bytes(32, 'little').hex(),
            'B': self.B.to_bytes(32, 'little').hex(),
            'C': self.C.to_bytes(32, 'little').hex(),
            'D': self.D.to_bytes(32, 'little').hex(),
            'nonce': self.nonce,
            'rounds': self.rounds,
            'sbox': bytes(self.sbox).hex(),
            'version': '2.1'
        }

    @classmethod
    def import_state(cls, state: Dict) -> 'TerraQuantum_v2_1':
        inst = cls.__new__(cls)
        inst.Q = 2**256 - 39
        inst.P = 2**255 - 19
        inst.CONST = 0x9E3779B97F4A7C159E3779B97F4A7C159E3779B97F4A7C159E3779B97F4A7C15
        inst.A = int.from_bytes(bytes.fromhex(state['A']), 'little')
        inst.B = int.from_bytes(bytes.fromhex(state['B']), 'little')
        inst.C = int.from_bytes(bytes.fromhex(state['C']), 'little')
        inst.D = int.from_bytes(bytes.fromhex(state['D']), 'little')
        inst.nonce = state['nonce']
        inst.rounds = state['rounds']
        inst.sbox = list(bytes.fromhex(state['sbox']))
        return inst

    @staticmethod
    def selftest() -> bool:
        test_key = b'\x00' * 32
        cipher = TerraQuantum_v2_1(test_key, nonce=0)
        stream = cipher.generate_stream(8)
        expected = "f9e03872b9b8d54f"
        if stream.hex() != expected:
            print(f"❌ Тест провален: {stream.hex()} != {expected}")
            return False
        print("✅ Самодиагностика пройдена")
        return True

if __name__ == "__main__":
    print("=" * 60)
    print("TERRA-QUANTUM v2.1 — ТЕСТ ШИФРОВАНИЯ")
    print("=" * 60)

    key = TerraQuantum_v2_1.generate_key(32)
    print(f"\n🔑 Ключ: {key.hex()}")

    text = "Привет, Хабр! Меня зовут Леонид."
    print(f"📝 Исходный текст: {text}")
    original_bytes = text.encode('utf-8')

    cipher_enc = TerraQuantum_v2_1(key, nonce=42)
    encrypted = cipher_enc.encrypt(original_bytes)
    print(f"🔒 Зашифровано (hex): {encrypted.hex()}")

    cipher_dec = TerraQuantum_v2_1(key, nonce=42)
    decrypted_bytes = cipher_dec.decrypt(encrypted)

    if original_bytes == decrypted_bytes:
        print("\n✅ ВСЁ РАБОТАЕТ ИДЕАЛЬНО!")
        try:
            print(f"🔓 Расшифровано: {decrypted_bytes.decode('utf-8')}")
        except:
            print(f"🔓 Расшифровано (байты): {decrypted_bytes}")
    else:
        print("\n❌ Ошибка расшифрования!")
