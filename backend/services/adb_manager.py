"""Safe, read-only communication with the locally installed ADB executable."""

from dataclasses import dataclass
import shutil
import subprocess
from pathlib import Path

from backend.config import ADB_EXECUTABLE, ADB_TIMEOUT_SECONDS, adb_candidates


class AdbError(RuntimeError):
    """An expected ADB execution or availability error."""


@dataclass(frozen=True)
class AdbDevice:
    serial: str
    state: str

    def as_dict(self) -> dict[str, str]:
        return {"serial": self.serial, "state": self.state}


class AdbManager:
    """Run a fixed ADB command set without invoking a shell."""

    def __init__(self, executable: str = ADB_EXECUTABLE, timeout: int = ADB_TIMEOUT_SECONDS):
        self.executable = executable
        self.timeout = timeout

    def _executable_path(self) -> str:
        for candidate in [self.executable, *adb_candidates()]:
            if shutil.which(candidate) or (candidate != self.executable and Path(candidate).is_file()):
                return candidate
        raise AdbError("ADB is not installed or is not available on PATH.")

    def list_devices(self) -> list[AdbDevice]:
        """Return devices reported by ``adb devices``.

        Malformed and informational lines are ignored. ADB failures become
        ``AdbError`` so the API can return a safe, useful message.
        """
        executable = self._executable_path()

        try:
            result = subprocess.run(
                [executable, "devices"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdbError("ADB did not respond before the command timeout.") from exc
        except OSError as exc:
            raise AdbError("ADB could not be started.") from exc

        if result.returncode != 0:
            detail = result.stderr.strip() or "ADB returned an error."
            raise AdbError(detail)

        devices: list[AdbDevice] = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices"):
                continue
            fields = line.split()
            if len(fields) >= 2:
                devices.append(AdbDevice(serial=fields[0], state=fields[1]))
        return devices

    def shell(self, serial: str, arguments: list[str]) -> str:
        """Run an internally selected read-only shell command for one device."""
        from backend.config import SERIAL_PATTERN

        if not serial or not arguments or any(not isinstance(value, str) for value in arguments):
            raise AdbError("Invalid ADB command parameters.")
        if not SERIAL_PATTERN.match(serial) or serial.startswith("-"):
            raise AdbError("Invalid ADB device serial format.")
        executable = self._executable_path()
        try:
            result = subprocess.run(
                [executable, "-s", serial, "shell", *arguments],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdbError("ADB did not respond before the command timeout.") from exc
        except OSError as exc:
            raise AdbError("ADB could not be started.") from exc
        if result.returncode != 0:
            raise AdbError(result.stderr.strip() or "ADB shell command failed.")
        return (result.stdout or "").strip()