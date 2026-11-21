"""The ESP32-WROOM-32 profile must match the Espressif documentation and the team's board reference."""

import json

import pytest

from backend.config import DATABASES
from backend.hardware.profiles import ProfileError, board_info, list_profiles, load_profile, resolve_profile

PROFILE = load_profile("esp32_wroom_32")
GPIO = PROFILE["gpio"]


def test_34_gpios_exist():
    # ESP-IDF: GPIO0~19, 21~23, 25~27, 32~39
    expected = [*range(0, 20), 21, 22, 23, 25, 26, 27, *range(32, 40)]
    assert PROFILE["valid_gpio_numbers"] == expected and sorted(map(int, GPIO)) == expected
    for missing in (20, 24, 28, 29, 30, 31, 40):
        assert str(missing) not in GPIO


def test_input_only_pins():
    assert sorted(int(n) for n, p in GPIO.items() if p["input_only"]) == [34, 35, 36, 37, 38, 39]
    for n in (34, 35, 36, 39):
        assert GPIO[str(n)]["output"] is False and GPIO[str(n)]["internal_pull_resistors"] is False
    assert GPIO["23"]["output"] is True and GPIO["23"]["input_only"] is False


def test_flash_pins_and_module_exposure():
    assert sorted(int(n) for n, p in GPIO.items() if p["flash_connected"]) == [6, 7, 8, 9, 10, 11]
    assert GPIO["6"]["module_pin"] == "SCK/CLK" and GPIO["11"]["module_pin"] == "SCS/CMD"
    assert sorted(int(n) for n, p in GPIO.items() if not p["exposed_on_module"]) == [37, 38]


def test_strapping_and_jtag():
    assert sorted(int(n) for n, p in GPIO.items() if p["strapping"]) == [0, 2, 5, 12, 15]
    straps = PROFILE["strapping_pins"]
    assert (straps["0"]["default_pull"], straps["2"]["default_pull"], straps["12"]["default_pull"],
            straps["15"]["default_pull"], straps["5"]["default_pull"]) == (
        "pull-up", "pull-down", "pull-down", "pull-up", "pull-up")  # datasheet Table 3
    assert PROFILE["jtag_pins"] == {"MTDI": 12, "MTCK": 13, "MTMS": 14, "MTDO": 15}


def test_analog_and_touch_channels():
    assert GPIO["36"]["adc"] == "ADC1_CH0" and GPIO["39"]["adc"] == "ADC1_CH3"
    assert GPIO["4"]["adc"] == "ADC2_CH0" and GPIO["26"]["adc"] == "ADC2_CH9"
    assert [int(n) for n, p in GPIO.items() if p["dac"]] == [25, 26]
    touch = {p["touch"]: int(n) for n, p in GPIO.items() if p["touch"]}
    # datasheet Table 11
    assert touch == {"T0": 4, "T1": 0, "T2": 2, "T3": 15, "T4": 13, "T5": 12, "T6": 14, "T7": 27, "T8": 33, "T9": 32}
    assert GPIO["0"]["rtc_gpio"] == "RTC_GPIO11" and GPIO["36"]["rtc_gpio"] == "RTC_GPIO0"


def test_sources_are_recorded():
    urls = [s["url"] for s in PROFILE["sources"]]
    assert "https://documentation.espressif.com/esp32-wroom-32_datasheet_en.html" in urls
    assert any("esp-idf" in u for u in urls)
    assert PROFILE["verification"]["verified_on"]
    assert all(p["source"] for p in GPIO.values())


def test_agrees_with_team_devkit_reference():
    reference = json.loads((DATABASES / "reference" / "esp32_devkit_v1_30pin.json").read_text(encoding="utf-8"))
    for name, pin in reference["gpio_pins"].items():
        entry = GPIO[name.removeprefix("GPIO")]
        for function in pin["functions"]:
            if function.startswith("ADC"):
                assert entry["adc"] == function, (name, function)
            elif function.startswith("Touch"):
                assert entry["touch"] == "T" + function.removeprefix("Touch"), (name, function)
            elif function.startswith("DAC"):
                assert entry["dac"] == "DAC_" + function.removeprefix("DAC"), (name, function)
            elif function == "Digital Input Only":
                assert entry["input_only"], name
            elif function == "Digital I/O":
                assert entry["output"], name
    restrictions = reference["restrictions"]
    assert set(restrictions["flash_reserved"]) == {int(n) for n, p in GPIO.items() if p["flash_connected"]}
    assert set(restrictions["boot_strapping"]) == {int(n) for n, p in GPIO.items() if p["strapping"]}
    assert set(restrictions["input_only"]) <= {int(n) for n, p in GPIO.items() if p["input_only"]}
    assert set(reference["peripherals"]["ADC1"]) <= {int(n) for n, p in GPIO.items() if p["adc_unit"] == 1}
    assert set(reference["peripherals"]["ADC2"]) == {int(n) for n, p in GPIO.items() if p["adc_unit"] == 2}


def test_profile_resolution():
    assert resolve_profile("ESP32-WROOM-32") == "esp32_wroom_32"
    assert resolve_profile("esp32") == "esp32_wroom_32"
    with pytest.raises(ProfileError, match="No verified hardware profile for ESP32-S3"):
        resolve_profile("ESP32-S3")
    with pytest.raises(ProfileError, match="Unknown chip profile"):
        resolve_profile("Raspberry Pi")
    assert {p["id"]: p["supported"] for p in list_profiles()}["esp32_wroom_32"] is True


def test_board_index_from_registry():
    assert board_info("esp32dev")["mcu"] == "ESP32"
    assert board_info("esp32doit-devkit-v1")["mcu"] == "ESP32"
    assert board_info("esp32-s3-devkitc-1")["mcu"] == "ESP32S3"
    assert board_info("no_such_board") is None
