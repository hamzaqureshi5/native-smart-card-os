# SPDX-License-Identifier: MIT
"""
A reader, in Python.

This class plays the role a physical card reader plays: it powers the card up,
reads the ATR, sends command APDUs and collects responses. It speaks the
simulator's line-oriented hex protocol over a pipe.

The point of keeping this thin is portability of the TESTS. Only the transport
inside this file knows what it is talking to, so the same suite drives:

  target="native"  the x86 simulator over a pipe            (default)
  target="qemu"    the ARM Cortex-M3 firmware over QEMU's UART
  target=...       a real reader via pyscard -- not yet written, but it is the
                   same one-method change

Set SCOS_TARGET=qemu (plus SCOS_FIRMWARE) to run any test against ARM. That is
the payoff: the integration suite is a conformance suite for the port rather
than something that has to be rewritten for it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional, Union


class CardError(RuntimeError):
    """The card or the link misbehaved (as opposed to returning an error SW)."""


def hexs(data: bytes) -> str:
    """Render bytes the way card documentation does: '00 A4 00 00'."""
    return " ".join(f"{b:02X}" for b in data)


def _to_bytes(apdu: Union[str, bytes, bytearray]) -> bytes:
    if isinstance(apdu, (bytes, bytearray)):
        return bytes(apdu)
    cleaned = "".join(ch for ch in apdu if ch not in " \t\r\n:")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"APDU hex has an odd number of digits: {apdu!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"not valid hex: {apdu!r}") from exc


@dataclass(frozen=True)
class Response:
    """A response APDU: optional data followed by SW1 SW2."""

    data: bytes
    sw: int

    @property
    def sw1(self) -> int:
        return (self.sw >> 8) & 0xFF

    @property
    def sw2(self) -> int:
        return self.sw & 0xFF

    @property
    def ok(self) -> bool:
        return self.sw == 0x9000

    def __str__(self) -> str:
        body = f"{hexs(self.data)} " if self.data else ""
        return f"{body}{self.sw:04X}"

    def __repr__(self) -> str:
        return f"<Response data={hexs(self.data) or '-'} sw={self.sw:04X}>"


# Status words we assert on often enough to name. Keep in step with
# include/apdu/sw.h.
SW_OK = 0x9000
SW_WRONG_LENGTH = 0x6700
SW_CHANNEL_UNSUPPORTED = 0x6881
SW_SM_UNSUPPORTED = 0x6882
SW_CHAINING_UNSUPPORTED = 0x6884
SW_SECURITY_NOT_SATISFIED = 0x6982
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_FUNC_NOT_SUPPORTED = 0x6A81
SW_FILE_NOT_FOUND = 0x6A82
SW_INCORRECT_P1P2 = 0x6A86
SW_LC_INCONSISTENT_P1P2 = 0x6A87
SW_INS_NOT_SUPPORTED = 0x6D00
SW_CLA_NOT_SUPPORTED = 0x6E00


def default_firmware_path() -> str:
    """Locate the SCV1 firmware ELF."""
    env = os.environ.get("SCOS_FIRMWARE")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", "..", ".."))
    candidate = os.path.join(root, "build-arm", "smartcard-os.elf")
    if os.path.isfile(candidate):
        return candidate
    raise CardError(
        "cannot find the SCV1 firmware; set SCOS_FIRMWARE, or build it with\n"
        "  cmake -S . -B build-arm "
        "-DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-scv1.cmake && "
        "cmake --build build-arm"
    )


def default_simulator_path() -> str:
    """Locate smartcard-sim: $SMARTCARD_SIM, then $PATH, then the build tree."""
    env = os.environ.get("SMARTCARD_SIM")
    if env:
        return env
    found = shutil.which("smartcard-sim")
    if found:
        return found
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", "..", ".."))
    for candidate in (
        os.path.join(root, "build", "smartcard-sim"),
        os.path.join(root, "smartcard-sim"),
    ):
        if os.path.isfile(candidate):
            return candidate
    raise CardError(
        "cannot find smartcard-sim; set SMARTCARD_SIM to its path"
    )


class SmartCard:
    """
    A powered-up simulated card.

    Use as a context manager so the card is always powered down -- which is
    also what flushes persistent memory:

        with SmartCard() as card:
            assert card.send_apdu("00A40000023F00").sw == 0x9000
    """

    def __init__(
        self,
        path: Optional[str] = None,
        state_dir: Optional[str] = None,
        seed: int = 1,
        extra_args: Optional[list] = None,
        timeout: float = 10.0,
        target: Optional[str] = None,
    ) -> None:
        self.target = target or os.environ.get("SCOS_TARGET", "native")
        self.timeout = timeout if self.target == "native" else max(timeout, 60.0)
        self._log: list = []
        cwd = None

        if self.target == "qemu":
            # The ARM firmware has no command line -- a chip has no argv. So
            # options that are flags on the native build become properties of
            # the emulated machine, and NVM persistence is a semihosting file in
            # QEMU's working directory.
            self.path = path or default_firmware_path()
            qemu = os.environ.get("SCOS_QEMU", "qemu-system-arm")
            cwd = state_dir or tempfile.mkdtemp(prefix="scos-qemu-")
            self._tempdir = None if state_dir else cwd
            argv = [
                qemu,
                "-M", "mps2-an385",
                "-cpu", "cortex-m3",
                # -nographic muxes the serial port with the QEMU monitor, which
                # swallows stdin. These three flags give a clean, exclusive UART.
                "-display", "none",
                "-monitor", "none",
                "-serial", "stdio",
                "-semihosting-config", "enable=on,target=native",
                "-kernel", self.path,
            ]
            if extra_args:
                argv += list(extra_args)
        elif self.target == "native":
            self.path = path or default_simulator_path()
            self._tempdir = None
            argv = [self.path, "--quiet", "--seed", str(seed)]
            if state_dir is not None:
                argv += ["--state-dir", state_dir]
            if extra_args:
                argv += list(extra_args)
        else:
            raise CardError(f"unknown target {self.target!r}")

        # stderr is captured separately: the native simulator keeps banner and
        # diagnostics off stdout precisely so stdout is a clean response stream.
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=cwd,
        )

        if self.target == "qemu":
            self._await_boot()

    # --- lifecycle --------------------------------------------------------

    def __enter__(self) -> "SmartCard":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _await_boot(self) -> None:
        """Consume the firmware banner up to 'Waiting for APDU...'.

        On the ARM target the UART is the ONLY channel, so the banner shares it
        with responses -- unlike the native build, where the banner goes to
        stderr. Skipping it here keeps every test above this line identical for
        both targets.
        """
        deadline = 400
        for _ in range(deadline):
            line = self.proc.stdout.readline()
            if line == "":
                raise CardError(
                    "firmware produced no banner; "
                    f"stderr:\n{self._drain_stderr()}"
                )
            self._log.append(f"# {line.rstrip()}")
            if "Waiting for APDU" in line:
                return
        raise CardError("firmware banner never completed")

    def close(self) -> None:
        """Power the card down: '.quit', then wait for it to exit."""
        if self.proc.poll() is None:
            try:
                self._write(".quit")
            except (BrokenPipeError, OSError, CardError):
                pass
            try:
                self.proc.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=self.timeout)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if getattr(self, "_tempdir", None):
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None

    # --- transport --------------------------------------------------------

    def _write(self, line: str) -> None:
        if self.proc.stdin is None:
            raise CardError("simulator stdin is closed")
        if self.proc.poll() is not None:
            raise CardError(
                f"simulator exited with code {self.proc.returncode}; "
                f"stderr:\n{self._drain_stderr()}"
            )
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        self._log.append(f"> {line}")

    _HEX = set("0123456789ABCDEFabcdef")

    def _read(self) -> str:
        if self.proc.stdout is None:
            raise CardError("stdout is closed")
        # The ARM target shares one UART between responses and diagnostics, so
        # non-hex lines are logged and skipped. The native target separates them
        # by stream, so nothing is skipped there and a stray line would (rightly)
        # fail the test.
        for _ in range(64):
            line = self.proc.stdout.readline()
            if line == "":
                raise CardError(
                    "card stopped responding (link down). "
                    f"exit code {self.proc.poll()}; "
                    f"stderr:\n{self._drain_stderr()}"
                )
            line = line.strip()
            if self.target == "qemu" and (
                line == "" or any(c not in self._HEX for c in line)
            ):
                self._log.append(f"# {line}")
                continue
            self._log.append(f"< {line}")
            return line
        raise CardError("too many non-response lines from the card")

    def _drain_stderr(self) -> str:
        if self.proc.stderr is None:
            return "(none)"
        try:
            # Only safe once the process has exited, which is when we call it.
            return self.proc.stderr.read() or "(empty)"
        except (OSError, ValueError):
            return "(unavailable)"

    # --- card operations --------------------------------------------------

    def send_apdu(self, apdu: Union[str, bytes, bytearray]) -> Response:
        """Send one command APDU and return the response."""
        raw = _to_bytes(apdu)
        self._write(raw.hex().upper())
        reply = _to_bytes(self._read())
        if len(reply) < 2:
            raise CardError(
                f"response too short to contain a status word: {hexs(reply)}"
            )
        return Response(data=reply[:-2], sw=(reply[-2] << 8) | reply[-1])

    def send_raw(self, line: str) -> str:
        """Send an arbitrary transport line. For negative transport tests."""
        self._write(line)
        return self._read()

    def atr(self) -> bytes:
        return _to_bytes(self.send_raw(".atr"))

    def reset(self) -> bytes:
        """Warm reset. The card answers with its ATR, as a real one does."""
        return _to_bytes(self.send_raw(".reset"))

    def select(self, file_id: Union[int, str, bytes] = 0x3F00) -> Response:
        """SELECT by file identifier (P1=00, P2=00)."""
        if isinstance(file_id, int):
            fid = bytes([(file_id >> 8) & 0xFF, file_id & 0xFF])
        else:
            fid = _to_bytes(file_id)
        if len(fid) != 2:
            raise ValueError("a file identifier is exactly 2 bytes")
        return self.send_apdu(bytes([0x00, 0xA4, 0x00, 0x00, len(fid)]) + fid)

    @property
    def transcript(self) -> str:
        """Everything sent and received, for failure messages."""
        return "\n".join(self._log)
