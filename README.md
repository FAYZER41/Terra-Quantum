# Terra-Quantum v2.1

Пост-квантовый симметричный поточный шифр.

## Установка

```bash
pip install -e .
```

## Использование

```python
from terra_quantum import TerraQuantum_v2_1

# Генерация ключа
key = TerraQuantum_v2_1.generate_key(32)

# Шифрование
cipher = TerraQuantum_v2_1(key, nonce=42)
encrypted = cipher.encrypt(b"Hello, World!")

# Расшифрование
decrypted = cipher.decrypt(encrypted)
print(decrypted)  # b'Hello, World!'
```

## Тесты

```bash
pytest tests/
```

## Лицензия

MIT

## Контакты

Автор: Гусев Леонид  
Telegram: @Terra_Quantum
