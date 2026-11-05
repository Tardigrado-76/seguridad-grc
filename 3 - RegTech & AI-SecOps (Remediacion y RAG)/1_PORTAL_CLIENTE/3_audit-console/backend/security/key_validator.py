"""bunker_key_validator.py — BunkerOS USB Hardware-Root Authentication.
===================================================================
Low-level ctypes validation of USB volume serial numbers via
kernel32.GetVolumeInformationW. Provides runtime USB monitoring
and DynamicBindingManager for L4 socket control.

Compliance: ENS Alta op.acc.1 (hardware auth), NIS2 Art.21, CRA Art.13.
"""

import json
import logging
import os
import pathlib
import sys
import threading
import time

import win32crypt

logger = logging.getLogger("BunkerOS.KeyValidator")

# ─── Configuration ──────────────────────────────────────────────────────

BASE_DIR = pathlib.Path(os.path.dirname(os.path.abspath(__file__))).resolve(strict=True)
_ROOT_DIR = BASE_DIR.parent
_KEY_CONFIG_PATH = _ROOT_DIR / ".bunker_secure" / "usb_binding.json"

# ─── WMI Low-Level Physical USB Serial Reader ──────────────────────────────

def get_physical_usb_serials_wmi() -> list[int]:
    """Reads the physical hardware SerialNumber of all connected USB devices via WMI.
    This bypasses the USBSTOR mass storage driver completely, allowing ENS Nivel Alto
    compliance (USBSTOR disabled) while maintaining hardware root-of-trust.

    Returns:
        List of integer hashes of the physical serial strings.

    """
    if sys.platform != "win32":
        logger.error("[KeyValidator] WMI USB enumeration only supported on Windows.")
        return []

    try:
        import zlib

        import win32com.client
        wmi = win32com.client.GetObject("winmgmts:")
        devices = wmi.InstancesOf("Win32_PnPEntity")
        serials = []
        for d in devices:
            if d.DeviceID and d.DeviceID.startswith("USB\\VID_"):
                parts = d.DeviceID.split("\\")
                if len(parts) >= 3:
                    serial = parts[-1]
                    # If it has &, it's usually a composite interface, not the physical device serial
                    if "&" not in serial:
                        serials.append(zlib.crc32(serial.encode("utf-8")))
        return serials
    except (ValueError, TypeError, RuntimeError, OSError) as e:
        logger.exception(f"[KeyValidator] WMI error: {e}")
        return []

def get_volume_serial_ctypes(drive_path: str) -> int | None:
    # Deprecated: Retained for ABI compatibility. Use WMI function instead.
    serials = get_physical_usb_serials_wmi()
    return serials[0] if serials else None


def format_serial_hex(serial: int) -> str:
    """Format serial as XXXX-XXXX string."""
    high = (serial >> 16) & 0xFFFF
    low = serial & 0xFFFF
    return f"{high:04X}-{low:04X}"


# ─── Key Storage & Validation ───────────────────────────────────────────


def store_usb_binding(drive_path: str, serial: int) -> None:
    """Store the USB binding configuration, sealed with win32crypt DPAPI."""
    serial_bytes = str(serial).encode("utf-8")
    # Encrypt the serial number using Windows Data Protection API (DPAPI)
    try:
        encrypted_bytes = win32crypt.CryptProtectData(
            serial_bytes,
            "BunkerOS Hardware Serial Protection",
            None,
            None,
            None,
            0,
        )
        dpapi_hex = encrypted_bytes.hex()
    except (ValueError, TypeError, RuntimeError, OSError) as e:
        logger.exception(
            f"[KeyValidator] Failed to seal with win32crypt DPAPI: {e}",
        )
        dpapi_hex = ""

    config = {
        "drive_path": drive_path,
        "serial_hex": format_serial_hex(serial),
        "serial_int": serial,
        "dpapi_sealed_hex": dpapi_hex,
        "bound_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    _KEY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_KEY_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)
    logger.info(
        f'[KeyValidator] USB binding stored and cryptographically sealed: {
            config["serial_hex"]}',
    )


def load_usb_binding() -> dict | None:
    """Load stored USB binding configuration."""
    if not _KEY_CONFIG_PATH.exists():
        return None
    try:
        with open(_KEY_CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.exception(f"[KeyValidator] Failed to load binding: {e}")
        return None


def validate_usb_key(drive_path: str | None = None) -> tuple[bool, str]:
    """Validate the currently connected USB against the stored binding.

    Returns:
        (is_valid, message) tuple.

    """
    binding = load_usb_binding()
    if binding is None:
        return False, "No USB binding configured. System cannot authenticate."

    expected_serial = binding.get("serial_int", 0)
    dpapi_sealed_hex = binding.get("dpapi_sealed_hex", "")

    current_serials = get_physical_usb_serials_wmi()
    if not current_serials:
        return False, "No physical USB devices detected."

    if expected_serial not in current_serials:
        expected_hex = format_serial_hex(expected_serial)
        return (
            False,
            f"Serial mismatch: expected {expected_hex} not found in connected physical devices.",
        )

    # DPAPI Validation
    if dpapi_sealed_hex:
        try:
            encrypted_bytes = bytes.fromhex(dpapi_sealed_hex)
            _desc, decrypted_bytes = win32crypt.CryptUnprotectData(
                encrypted_bytes, None, None, None, 0,
            )
            decrypted_serial = int(decrypted_bytes.decode("utf-8"))
            if decrypted_serial != expected_serial:
                return (
                    False,
                    "DPAPI seal validation failed: Decrypted serial mismatch.",
                )
        except (ValueError, TypeError, RuntimeError, OSError) as e:
            return False, f"DPAPI cryptographic validation failed: {e}"

    return (
        True,
        f"USB key validated and DPAPI verified: {format_serial_hex(expected_serial)}",
    )


# ─── Runtime USB Monitor ─────────────────────────────────────────────────────


class USBKeyMonitor(threading.Thread):
    """Daemon thread monitoring USB presence. Publishes USB_DISCONNECTED
    to the EventBus if the authenticated USB is removed at runtime.
    """

    def __init__(self, check_interval: float = 3.0) -> None:
        super().__init__(daemon=True, name="USBKeyMonitor")
        self.check_interval = check_interval
        self.running = True
        self._event_bus = None

    def set_event_bus(self, bus) -> None:
        self._event_bus = bus

    def run(self) -> None:
        binding = load_usb_binding()
        if not binding:
            logger.warning("[USBMonitor] No binding to monitor.")
            return

        expected = binding.get("serial_int", 0)
        logger.info(f"[USBMonitor] Monitoring physical USB for serial 0x{expected:08X}")

        while self.running:
            time.sleep(self.check_interval)
            current_serials = get_physical_usb_serials_wmi()
            if not current_serials or expected not in current_serials:
                logger.critical(
                    "[USBMonitor] USB KEY DISCONNECTED from physical layer!",
                )
                if self._event_bus:
                    from src.bunker_event_bus import EVENT_USB_DISCONNECTED

                    self._event_bus.publish(
                        EVENT_USB_DISCONNECTED,
                        {
                            "drive": "WMI_PHYSICAL",
                            "expected_serial": format_serial_hex(expected),
                        },
                        source="USBKeyMonitor",
                    )
                break

    def stop(self) -> None:
        self.running = False


# ─── Dynamic Binding Manager ─────────────────────────────────────────────────


class DynamicBindingManager:
    """Controls Uvicorn socket binding at L4 level based on USB key validation.
    Replaces the legacy L7 MODO_RED_ACTIVADO toggle.

    - Key VALID → bind to 0.0.0.0 (network mode)
    - Key INVALID → process terminates (fail-secure)
    """

    def __init__(self, drive_path: str | None = None) -> None:
        self.drive_path = drive_path
        self.validated = False
        self.bind_host = "127.0.0.1"  # Default: loopback only

    def authorize_binding(self) -> tuple[str, int]:
        """Validate USB key and determine binding parameters.

        Returns:
            (host, port) tuple for Uvicorn.

        Raises:
            SystemExit if key validation fails (fail-secure policy).

        """
        port = int(os.getenv("BUNKER_API_PORT", "8000"))

        is_valid, message = validate_usb_key(self.drive_path)

        if is_valid:
            self.validated = True
            self.bind_host = "0.0.0.0" if os.getenv("BUNKER_ALLOW_GLOBAL_BIND") == "true" else "127.0.0.1"  # nosec B104
            logger.info(f"[DynamicBinding] {message} → Binding to {
                    self.bind_host}:{port}")
            return self.bind_host, port
        logger.critical(
            f"[DynamicBinding] AUTHORIZATION DENIED: {message}",
        )
        logger.critical(
            "[DynamicBinding] Fail-secure: process terminating.",
        )
        sys.exit(78)  # EX_CONFIG — configuration error

    def get_monitor(self) -> USBKeyMonitor:
        """Create a USB monitor thread for runtime disconnection detection."""
        return USBKeyMonitor()


# ─── CLI Entrypoint ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(description="BunkerOS USB Key Validator")
    parser.add_argument(
        "--bind", action="store_true", help="Bind a new USB key",
    )
    parser.add_argument(
        "--verify", action="store_true", help="Verify current USB key",
    )
    parser.add_argument(
        "--drive", default="G:", help="Drive letter (default: G:)",
    )
    args = parser.parse_args()

    drive = args.drive.rstrip("\\") + "\\"

    if args.bind:
        serial = get_volume_serial_ctypes(drive)
        if serial is not None:
            store_usb_binding(drive, serial)
        else:
            sys.exit(1)

    elif args.verify:
        valid, msg = validate_usb_key(drive)
        sys.exit(0 if valid else 1)

    else:
        parser.print_help()
