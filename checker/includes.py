"""Find the #include lines in a PlatformIO project's source code.

We only care about headers that must come from an external library. These are skipped:
  * headers that ship with the ESP32 Arduino core (WiFi.h, Wire.h, ...)
  * C / C++ standard headers and ESP-IDF headers (stdio.h, string, freertos/..., esp_wifi.h)
  * headers that exist inside the project itself (src/, include/, lib/)
"""

import re
from dataclasses import dataclass
from pathlib import Path

SOURCE_FOLDERS = ["src", "include", "lib"]
SOURCE_SUFFIXES = {".c", ".cpp", ".cc", ".h", ".hpp", ".ino"}

INCLUDE_LINE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)

# Headers provided by the ESP32 Arduino core (framework = arduino). No lib_deps needed.
FRAMEWORK_HEADERS = {
    "Arduino.h", "WiFi.h", "WiFiClient.h", "WiFiClientSecure.h", "WiFiServer.h", "WiFiUdp.h", "WiFiMulti.h",
    "WiFiAP.h", "WiFiGeneric.h", "WiFiSTA.h", "WiFiScan.h", "WiFiType.h", "WebServer.h", "HTTPClient.h",
    "HTTPUpdate.h", "HTTPUpdateServer.h", "Update.h", "Preferences.h", "SPI.h", "Wire.h", "FS.h", "SPIFFS.h",
    "LittleFS.h", "FFat.h", "SD.h", "SD_MMC.h", "EEPROM.h", "ESPmDNS.h", "ArduinoOTA.h", "BluetoothSerial.h",
    "BLEDevice.h", "BLEServer.h", "BLEClient.h", "BLEUtils.h", "BLE2902.h", "BLEScan.h", "BLEAdvertisedDevice.h",
    "BLEBeacon.h", "BLEHIDDevice.h", "Ticker.h", "DNSServer.h", "ETH.h", "I2S.h", "HardwareSerial.h", "Stream.h",
    "Print.h", "Network.h", "NetworkClient.h", "NetworkClientSecure.h", "NetworkUdp.h", "NetworkServer.h",
    "AsyncUDP.h", "USB.h", "USBHIDKeyboard.h", "USBHIDMouse.h", "esp32-hal.h", "pgmspace.h", "base64.h",
    "MD5Builder.h", "SHA1Builder.h", "StreamString.h", "WString.h", "IPAddress.h", "Esp.h", "esp_camera.h",
    "Matter.h", "Zigbee.h", "ESP_I2S.h", "ESP_SR.h", "esp_now.h",
}
# C / C++ standard library (written without .h for C++)
STANDARD_HEADERS = {
    "assert.h", "ctype.h", "errno.h", "float.h", "limits.h", "math.h", "setjmp.h", "signal.h", "stdarg.h",
    "stdbool.h", "stddef.h", "stdint.h", "stdio.h", "stdlib.h", "string.h", "time.h", "inttypes.h", "sys/time.h",
    "algorithm", "array", "atomic", "bitset", "cmath", "cstdint", "cstdio", "cstdlib", "cstring", "chrono",
    "functional", "iostream", "map", "memory", "mutex", "queue", "set", "sstream", "string", "thread", "tuple",
    "unordered_map", "utility", "vector", "deque", "list", "numeric", "optional", "type_traits", "climits",
}
# ESP-IDF / FreeRTOS / lwIP headers are always available on ESP32: match by prefix.
SYSTEM_PREFIXES = ("freertos/", "driver/", "esp_", "soc/", "hal/", "sys/", "lwip/", "mbedtls/", "nvs",
                   "rom/", "sdkconfig", "rtc_", "bt", "esp32/", "arpa/", "netinet/")


@dataclass
class Include:
    header: str     # e.g. "PubSubClient.h"
    file: str       # source file it was found in, relative to the project folder
    line: int


def find_source_files(project: Path) -> list[Path]:
    files = []
    for folder in SOURCE_FOLDERS:
        base = project / folder
        if base.is_dir():
            files += [p for p in base.rglob("*") if p.suffix.lower() in SOURCE_SUFFIXES]
    # Arduino-style projects sometimes keep the .ino next to platformio.ini
    files += [p for p in project.glob("*.ino")]
    return sorted(files)


def is_builtin(header: str) -> bool:
    return header in FRAMEWORK_HEADERS or header in STANDARD_HEADERS or header.startswith(SYSTEM_PREFIXES)


def find_external_includes(project: Path) -> list[Include]:
    """#include lines that need a library from outside the project."""
    sources = find_source_files(project)
    local_headers = {p.name for p in sources}          # headers the project ships itself
    found: list[Include] = []
    seen: set[str] = set()
    for path in sources:
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in INCLUDE_LINE.finditer(text):
            header = match.group(1).strip()
            if is_builtin(header) or Path(header).name in local_headers or header in seen:
                continue
            seen.add(header)
            line = text.count("\n", 0, match.start()) + 1
            found.append(Include(header=header, file=path.relative_to(project).as_posix(), line=line))
    return found
