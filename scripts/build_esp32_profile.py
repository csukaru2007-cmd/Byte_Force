"""Generate databases/esp32_wroom_32.json from transcribed Espressif tables.

    python -m scripts.build_esp32_profile

The pin data below is copied verbatim from the ESP32-WROOM-32 datasheet v3.8
(https://documentation.espressif.com/esp32-wroom-32_datasheet_en.html), Table 2
"Pin Definitions", and the ESP-IDF "GPIO Summary" table for the chip-level pins that the
module does not expose (GPIO37, GPIO38). Capabilities (ADC, DAC, touch, RTC, JTAG, input
only) are *derived* from these strings, not typed separately, so a transcription is
checked in one place. tests/unit/test_hardware_profile.py re-checks the result against
the datasheet facts and against the team's DevKit reference file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "databases" / "esp32_wroom_32.json"

DATASHEET = "https://documentation.espressif.com/esp32-wroom-32_datasheet_en.html"
IDF_GPIO = "https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/peripherals/gpio.html"
ARDUINO_VARIANT = "https://github.com/espressif/arduino-esp32/blob/master/variants/esp32/pins_arduino.h"
ARDUINO_GPIO_H = "https://github.com/espressif/arduino-esp32/blob/master/cores/esp32/esp32-hal-gpio.h"

# Datasheet v3.8, Table 2: Pin Definitions  (name, module pin number, type, function string)
TABLE_2 = [
    ("SENSOR_VP", 4, "I", "GPIO36, ADC1_CH0, RTC_GPIO0"),
    ("SENSOR_VN", 5, "I", "GPIO39, ADC1_CH3, RTC_GPIO3"),
    ("IO34", 6, "I", "GPIO34, ADC1_CH6, RTC_GPIO4"),
    ("IO35", 7, "I", "GPIO35, ADC1_CH7, RTC_GPIO5"),
    ("IO32", 8, "I/O", "GPIO32, XTAL_32K_P (32.768 kHz crystal oscillator input), ADC1_CH4, TOUCH9, RTC_GPIO9"),
    ("IO33", 9, "I/O", "GPIO33, XTAL_32K_N (32.768 kHz crystal oscillator output), ADC1_CH5, TOUCH8, RTC_GPIO8"),
    ("IO25", 10, "I/O", "GPIO25, DAC_1, ADC2_CH8, RTC_GPIO6, EMAC_RXD0"),
    ("IO26", 11, "I/O", "GPIO26, DAC_2, ADC2_CH9, RTC_GPIO7, EMAC_RXD1"),
    ("IO27", 12, "I/O", "GPIO27, ADC2_CH7, TOUCH7, RTC_GPIO17, EMAC_RX_DV"),
    ("IO14", 13, "I/O", "GPIO14, ADC2_CH6, TOUCH6, RTC_GPIO16, MTMS, HSPICLK, HS2_CLK, SD_CLK, EMAC_TXD2"),
    ("IO12", 14, "I/O", "GPIO12, ADC2_CH5, TOUCH5, RTC_GPIO15, MTDI, HSPIQ, HS2_DATA2, SD_DATA2, EMAC_TXD3"),
    ("IO13", 16, "I/O", "GPIO13, ADC2_CH4, TOUCH4, RTC_GPIO14, MTCK, HSPID, HS2_DATA3, SD_DATA3, EMAC_RX_ER"),
    ("SHD/SD2", 17, "I/O", "GPIO9, SD_DATA2, SPIHD, HS1_DATA2, U1RXD"),
    ("SWP/SD3", 18, "I/O", "GPIO10, SD_DATA3, SPIWP, HS1_DATA3, U1TXD"),
    ("SCS/CMD", 19, "I/O", "GPIO11, SD_CMD, SPICS0, HS1_CMD, U1RTS"),
    ("SCK/CLK", 20, "I/O", "GPIO6, SD_CLK, SPICLK, HS1_CLK, U1CTS"),
    ("SDO/SD0", 21, "I/O", "GPIO7, SD_DATA0, SPIQ, HS1_DATA0, U2RTS"),
    ("SDI/SD1", 22, "I/O", "GPIO8, SD_DATA1, SPID, HS1_DATA1, U2CTS"),
    ("IO15", 23, "I/O", "GPIO15, ADC2_CH3, TOUCH3, MTDO, HSPICS0, RTC_GPIO13, HS2_CMD, SD_CMD, EMAC_RXD3"),
    ("IO2", 24, "I/O", "GPIO2, ADC2_CH2, TOUCH2, RTC_GPIO12, HSPIWP, HS2_DATA0, SD_DATA0"),
    ("IO0", 25, "I/O", "GPIO0, ADC2_CH1, TOUCH1, RTC_GPIO11, CLK_OUT1, EMAC_TX_CLK"),
    ("IO4", 26, "I/O", "GPIO4, ADC2_CH0, TOUCH0, RTC_GPIO10, HSPIHD, HS2_DATA1, SD_DATA1, EMAC_TX_ER"),
    ("IO16", 27, "I/O", "GPIO16, HS1_DATA4, U2RXD, EMAC_CLK_OUT"),
    ("IO17", 28, "I/O", "GPIO17, HS1_DATA5, U2TXD, EMAC_CLK_OUT_180"),
    ("IO5", 29, "I/O", "GPIO5, VSPICS0, HS1_DATA6, EMAC_RX_CLK"),
    ("IO18", 30, "I/O", "GPIO18, VSPICLK, HS1_DATA7"),
    ("IO19", 31, "I/O", "GPIO19, VSPIQ, U0CTS, EMAC_TXD0"),
    ("IO21", 33, "I/O", "GPIO21, VSPIHD, EMAC_TX_EN"),
    ("RXD0", 34, "I/O", "GPIO3, U0RXD, CLK_OUT2"),
    ("TXD0", 35, "I/O", "GPIO1, U0TXD, CLK_OUT3, EMAC_RXD2"),
    ("IO22", 36, "I/O", "GPIO22, VSPIWP, U0RTS, EMAC_TXD1"),
    ("IO23", 37, "I/O", "GPIO23, VSPID, HS1_STROBE"),
]

# ESP-IDF GPIO Summary: chip GPIOs that exist on ESP32 but are not module pins of WROOM-32
CHIP_ONLY = [
    (37, "GPIO37, ADC1_CH1, RTC_GPIO1"),
    (38, "GPIO38, ADC1_CH2, RTC_GPIO2"),
]

# ESP-IDF: "The ESP32 chip features 34 physical GPIO pins
# (GPIO0 ~ GPIO19, GPIO21 ~ GPIO23, GPIO25 ~ GPIO27, and GPIO32 ~ GPIO39)"
CHIP_GPIOS = [*range(0, 20), 21, 22, 23, 25, 26, 27, *range(32, 40)]

# Datasheet Table 3: Default Configuration of Strapping Pins + sections 3.1-3.4
STRAPPING = {
    0: {"signal": "GPIO0", "default_pull": "pull-up", "default_value": 1,
        "controls": "Chip boot mode (with GPIO2): 1 = SPI boot, 0 = joint download boot",
        "risk_when_driven": "Held low at reset, the chip enters download mode instead of running the firmware."},
    2: {"signal": "GPIO2", "default_pull": "pull-down", "default_value": 0,
        "controls": "Chip boot mode (with GPIO0): must be 0 for download boot",
        "risk_when_driven": "Held high at reset while GPIO0 is low, download boot cannot be entered (flashing fails)."},
    5: {"signal": "GPIO5", "default_pull": "pull-up", "default_value": 1,
        "controls": "Timing of SDIO slave (with MTDO)",
        "risk_when_driven": "Changes the SDIO slave sampling/output edge at reset; relevant only when the ESP32 is used as an SDIO slave."},
    12: {"signal": "MTDI", "default_pull": "pull-down", "default_value": 0,
         "controls": "Internal LDO (VDD_SDIO) voltage: 0 = 3.3 V (from VDD3P3_RTC), 1 = 1.8 V internal LDO",
         "risk_when_driven": "Held high at reset, VDD_SDIO switches to 1.8 V. A module fitted with 3.3 V flash then fails to boot (unless EFUSE_SDIO_FORCE overrides the pin)."},
    15: {"signal": "MTDO", "default_pull": "pull-up", "default_value": 1,
         "controls": "U0TXD printing during boot (1 = enabled) and timing of SDIO slave (with GPIO5)",
         "risk_when_driven": "Held low at reset, ROM boot messages on U0TXD are silenced."},
}

JTAG = {"MTDI": 12, "MTCK": 13, "MTMS": 14, "MTDO": 15}


def parse_functions(text: str) -> list[str]:
    return [part.strip() for part in text.split(",")]


def gpio_entry(gpio: int, functions: list[str], *, module_pin: str | None, pin_number: int | None,
               pin_type: str, exposed: bool, source: str) -> dict:
    joined = " ".join(functions)
    adc = re.search(r"ADC([12])_CH(\d)", joined)
    touch = re.search(r"TOUCH(\d)", joined)
    dac = re.search(r"DAC_(\d)", joined)
    rtc = re.search(r"RTC_GPIO(\d+)", joined)
    jtag = next((name for name in JTAG if name in functions), None)
    input_only = pin_type == "I"
    flash = module_pin in ("SHD/SD2", "SWP/SD3", "SCS/CMD", "SCK/CLK", "SDO/SD0", "SDI/SD1")
    return {
        "gpio": gpio,
        "module_pin": module_pin,
        "module_pin_number": pin_number,
        "exposed_on_module": exposed,
        "datasheet_type": pin_type,
        "input": True,
        "output": not input_only,
        "input_only": input_only,
        # ESP-IDF: "GPIO34-39 can only be set as input mode and do not have software-enabled pullup or pulldown functions"
        "internal_pull_resistors": not (34 <= gpio <= 39),
        "adc": f"ADC{adc.group(1)}_CH{adc.group(2)}" if adc else None,
        "adc_unit": int(adc.group(1)) if adc else None,
        "dac": f"DAC_{dac.group(1)}" if dac else None,
        "touch": f"T{touch.group(1)}" if touch else None,
        "rtc_gpio": f"RTC_GPIO{rtc.group(1)}" if rtc else None,
        "flash_connected": flash,
        "strapping": gpio in STRAPPING,
        "jtag": jtag,
        "uart0": {"U0TXD": "TX", "U0RXD": "RX"}.get(next((f for f in functions if f in ("U0TXD", "U0RXD")), ""), None),
        "iomux_functions": functions,
        "source": source,
    }


def main() -> None:
    gpio: dict[str, dict] = {}
    for module_pin, number, pin_type, text in TABLE_2:
        functions = parse_functions(text)
        number_gpio = int(functions[0].removeprefix("GPIO"))
        gpio[str(number_gpio)] = gpio_entry(number_gpio, functions, module_pin=module_pin, pin_number=number,
                                            pin_type=pin_type, exposed=True,
                                            source="ESP32-WROOM-32 datasheet v3.8, Table 2")
    for number_gpio, text in CHIP_ONLY:
        gpio[str(number_gpio)] = gpio_entry(number_gpio, parse_functions(text), module_pin=None, pin_number=None,
                                            pin_type="I", exposed=False,
                                            source="ESP-IDF GPIO Summary (chip pin, not a WROOM-32 module pin)")
    assert sorted(map(int, gpio)) == CHIP_GPIOS, "every chip GPIO must be described exactly once"
    ordered = {str(n): gpio[str(n)] for n in CHIP_GPIOS}

    profile = {
        "profile_id": "esp32_wroom_32",
        "chip_id": "esp32",
        "chip_family": "ESP32",
        "chip": "ESP32-D0WDQ6",
        "module": "ESP32-WROOM-32",
        "display_name": "ESP32-WROOM-32 (original ESP32)",
        "aliases": ["ESP32-WROOM-32", "esp32_wroom_32", "esp32", "ESP32"],
        "applies_to_mcu": "ESP32",
        "status_note": "The datasheet v3.8 marks ESP32-WROOM-32 as Not Recommended For New Designs (NRND).",
        "sources": [
            {"id": "wroom32_datasheet", "title": "ESP32-WROOM-32 Datasheet", "version": "v3.8", "url": DATASHEET,
             "used_for": ["Table 2 Pin Definitions", "Table 3 Default Configuration of Strapping Pins",
                          "3.1-3.5 Boot Configurations", "Table 11 Capacitive-Sensing GPIOs", "GPIO6-GPIO11 flash note"]},
            {"id": "esp_idf_gpio", "title": "ESP-IDF Programming Guide (ESP32): GPIO & RTC GPIO", "version": "latest",
             "url": IDF_GPIO, "used_for": ["GPIO summary (34 GPIOs)", "GPIO37/GPIO38", "input-only GPIO34-39 without pull resistors",
                                           "ADC2 unavailable with Wi-Fi", "JTAG GPIO12-15", "GPIO36/39 interrupt erratum"]},
            {"id": "arduino_variant", "title": "arduino-esp32 variants/esp32/pins_arduino.h", "url": ARDUINO_VARIANT,
             "used_for": ["Arduino default pin aliases (SDA, SCL, SPI, A*, T*, DAC*)"]},
            {"id": "arduino_gpio_h", "title": "arduino-esp32 cores/esp32/esp32-hal-gpio.h", "url": ARDUINO_GPIO_H,
             "used_for": ["pinMode mode constants"]},
        ],
        "verification": {
            "verified_on": "2026-11-21",
            "method": "Datasheet HTML and ESP-IDF page were downloaded and the tables transcribed verbatim into "
                      "scripts/build_esp32_profile.py; capabilities are derived from the transcribed function strings.",
            "checked_by": "tests/unit/test_hardware_profile.py",
        },
        "valid_gpio_numbers": CHIP_GPIOS,
        "nonexistent_gpio_note": "GPIO20, GPIO24 and GPIO28-GPIO31 are not GPIOs of the ESP32 (D0WD) chip; numbers above 39 do not exist.",
        "gpio": ordered,
        "flash_pins": {str(g["gpio"]): g["module_pin"] for g in ordered.values() if g["flash_connected"]},
        "flash_note": "Pins SCK/CLK, SDO/SD0, SDI/SD1, SHD/SD2, SWP/SD3 and SCS/CMD, namely GPIO6 to GPIO11, are connected to the SPI flash integrated on the module and are not recommended for other uses. (Datasheet v3.8, Table 2 note 2)",
        "strapping_pins": {str(k): v for k, v in STRAPPING.items()},
        "strapping_note": "Strapping pins are latched at power-up/reset. Configuring them in software after boot is allowed; the risk comes from external circuitry that holds them at a non-default level during reset.",
        "jtag_pins": JTAG,
        "jtag_note": "GPIO12-15 are usually used for inline debug (ESP-IDF). Using them as GPIO disables external JTAG debugging on those pins; it is not evidence that debugging is exposed.",
        "uart0": {"tx": 1, "rx": 3, "note": "TXD & RXD are usually used for flashing and debugging (ESP-IDF)."},
        "adc2_wifi_conflict": "ADC2 pins cannot be used when Wi-Fi is used (ESP-IDF GPIO summary).",
        "gpio36_39_interrupt_note": "Do not use the interrupt of GPIO36 and GPIO39 when using ADC or Wi-Fi and Bluetooth with sleep mode enabled (ESP-IDF, ESP32 ECO workaround GPIO-3.11).",
        "dac_channels": {"DAC_1": 25, "DAC_2": 26},
        "arduino_variant_defaults": {
            "source": ARDUINO_VARIANT,
            "pins": {"TX": 1, "RX": 3, "SDA": 21, "SCL": 22, "SS": 5, "MOSI": 23, "MISO": 19, "SCK": 18,
                     "A0": 36, "A3": 39, "A4": 32, "A5": 33, "A6": 34, "A7": 35, "A10": 4, "A11": 0, "A12": 2,
                     "A13": 15, "A14": 13, "A15": 12, "A16": 14, "A17": 27, "A18": 25, "A19": 26,
                     "T0": 4, "T1": 0, "T2": 2, "T3": 15, "T4": 13, "T5": 12, "T6": 14, "T7": 27, "T8": 33, "T9": 32,
                     "DAC1": 25, "DAC2": 26},
            "note": "The generic 'esp32' variant (board esp32dev) does not define LED_BUILTIN.",
        },
    }
    OUTPUT.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(ordered)} GPIOs)")


if __name__ == "__main__":
    main()
