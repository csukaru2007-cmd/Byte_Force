import pytest

from backend.platformio.package_intel import load_trusted_packages
from backend.platformio.similarity import best_match, compact, compare, describe_difference, tokens


def test_normalisation():
    assert compact("Adafruit BME280 Library") == compact("Adafruit_BME280") == "adafruitbme280"
    assert tokens("PubSubClient") == ["pub", "sub", "client"]
    assert compact("ESP Async WebServer") == compact("ESPAsyncWebServer")


@pytest.mark.parametrize("candidate, trusted, relation", [
    ("adafruit_bme280", "Adafruit BME280 Library", "exact"),            # case + separators
    ("Adafruit BME28O Library", "Adafruit BME280 Library", "confusable"),  # O for 0
    ("PubSubCIient", "PubSubClient", "confusable"),                      # capital I for l
    ("ArduinoJsom", "ArduinoJson", "edit"),                              # substitution
    ("ArduinoJsn", "ArduinoJson", "edit"),                               # deletion
    ("ArduinoJsonn", "ArduinoJson", "edit"),                             # insertion
    ("ArudinoJson", "ArduinoJson", "edit"),                              # adjacent swap
    ("ArduinoJson-v7", "ArduinoJson", "edit"),                           # 2 added chars = edit
    ("ArduinoJsonPro", "ArduinoJson", "extra_words"),                    # short affix
    ("NeoPixel", "Adafruit NeoPixel", None),                             # only 2 trusted words
    ("Adafruit Unified", "Adafruit Unified Sensor", "missing_words"),
    ("Adafruit DHT sensor", "DHT sensor library", None),
])
def test_relations(candidate, trusted, relation):
    assert compare(candidate, trusted)[0] == relation


@pytest.mark.parametrize("candidate", ["WiFi", "SPI", "Servo", "LiquidCrystal", "Blynk", "ESP32Servo",
                                       "FastLED NeoMatrix", "U8g2_for_Adafruit_GFX"])
def test_unrelated_or_extension_names_do_not_match(candidate):
    assert best_match(candidate, load_trusted_packages()) is None


def test_short_names_are_not_edit_compared():
    assert compare("SPl", "SPI")[0] != "edit"


def test_best_match_prefers_strongest_relation_and_explains():
    match = best_match("Adafruit_BME28O", load_trusted_packages())
    assert match.trusted_name == "Adafruit BME280 Library"
    assert match.relation == "confusable"
    assert "'0' replaced by 'o'" in match.difference
    assert 0.9 <= match.similarity_score < 1.0


def test_describe_difference():
    assert describe_difference("ArduinoJsom", "ArduinoJson") == "'n' replaced by 'm'"
    assert describe_difference("Adafruit_BME280", "Adafruit BME280 Library") == \
        "same name after normalising case and separators"
