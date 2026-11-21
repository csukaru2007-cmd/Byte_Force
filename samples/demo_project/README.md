# ShipSafe demo project (intentionally flawed)

A small ESP32 weather station used to demonstrate ShipSafe. It is **not** a real product.
Everything it contains is harmless: credentials are fake and network addresses are
example / documentation addresses that do not belong to anyone.

What ShipSafe should find:

| Component | Issue |
|---|---|
| PlatformIO intelligence | `jasonlzt/FastLED` uses the name of the verified `fastled/FastLED` package from another publisher |
| PlatformIO intelligence | `bblanch0n/ArduinoJson` does not exist in the registry (owner typo of `bblanchon`) |
| Hardware | `STATUS_LED_PIN` (build flag, = 34) is driven as an output; GPIO34 is input-only |
| Hardware | `analogRead(26)`: GPIO26 is an ADC2 channel, unusable while Wi-Fi is on |
| Security | `WIFI_PASSWORD` is a hardcoded (fake) credential |
| Security | `ArduinoOTA.begin()` without a password |
| Security | the local `RainGauge` "sensor" library uploads data over plain HTTP to a fixed address |

Ordinary MQTT publishing in `main.cpp` should only appear as an INFO-level network inventory.
