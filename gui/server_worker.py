"""
ServerWorker — встроенный VPN-сервер в фоновом потоке QThread.
Запускается автоматически при подключении к localhost,
делая приложение самодостаточным без отдельного server.py.
"""
import asyncio

from PyQt5.QtCore import QThread, pyqtSignal

from utils.app_paths import get_default_certs_dir


class ServerWorker(QThread):
    log_line = pyqtSignal(str, str)

    def __init__(self, certs_dir: str = "", parent=None):
        super().__init__(parent)
        self._certs_dir = certs_dir or str(get_default_certs_dir())
        self._loop: asyncio.AbstractEventLoop = None

    def run(self) -> None:
        from server import run_server
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(
                run_server(host="127.0.0.1", port=8443, certs_dir=self._certs_dir)
            )
        except FileNotFoundError as exc:
            self.log_line.emit(
                "ERROR",
                f"Встроенный сервер: сертификаты не найдены — {exc}. "
                "Сначала нажмите «Создать тестовые сертификаты».",
            )
        except Exception as exc:
            self.log_line.emit("ERROR", f"Встроенный сервер остановлен: {exc}")
        finally:
            self._loop.close()
            self._loop = None

    def stop(self) -> None:
        loop = self._loop
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(loop.stop)
        self.wait(2000)
