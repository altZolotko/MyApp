"""
Модуль безопасного затирания памяти.

Назначение: уничтожение криптографических ключей и чувствительных данных в памяти
после завершения их использования, во избежание утечки через дамп памяти или
сборщик мусора Python.

Реализуемые требования: НФТ-4 (сертифицируемость), Д (безопасное обращение с ключами).
"""

import ctypes
import os
from contextlib import contextmanager
from typing import Generator


def zeroize(data: bytearray) -> None:
    """
    Затирает содержимое bytearray нулями через ctypes.memset.

    Использует ctypes для прямой записи в память, обходя GC Python.
    Вызывается после окончания использования любого криптоматериала.

    :param data: изменяемый буфер с ключевым материалом
    """
    if not isinstance(data, bytearray):
        raise TypeError("Затирание поддерживается только для bytearray")
    length = len(data)
    if length == 0:
        return
    arr = (ctypes.c_char * length).from_buffer(data)
    ctypes.memset(arr, 0, length)


def zeroize_bytes(buf: bytearray) -> None:
    """
    Обнуляет bytearray через прямой доступ к памяти.

    :param buf: буфер для затирания
    """
    if len(buf) == 0:
        return
    mv = memoryview(buf)
    for i in range(len(buf)):
        mv[i] = 0


class SecureBuffer:
    """
    Контекстный менеджер для безопасного хранения чувствительных данных.

    Гарантирует затирание буфера при выходе из контекста, даже при исключениях.
    Используется для хранения сессионных ключей, временных ECDH-параметров
    и прочего криптоматериала.

    Пример использования::

        with SecureBuffer(32) as buf:
            buf[:] = my_secret_key
            # работа с buf
        # здесь buf уже обнулён
    """

    def __init__(self, size: int) -> None:
        """
        :param size: размер буфера в байтах
        """
        self._buf: bytearray = bytearray(size)
        self._size: int = size

    def __enter__(self) -> bytearray:
        return self._buf

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()

    def wipe(self) -> None:
        """Принудительно затирает буфер."""
        zeroize_bytes(self._buf)

    @property
    def data(self) -> bytearray:
        return self._buf


@contextmanager
def secure_context(initial: bytes) -> Generator[bytearray, None, None]:
    """
    Контекстный менеджер: копирует bytes в bytearray, затирает по завершении.

    :param initial: исходные байты (неизменяемые)
    :yields: изменяемый буфер с данными
    """
    buf = bytearray(initial)
    try:
        yield buf
    finally:
        zeroize_bytes(buf)
