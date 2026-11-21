// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
class ArduinoOTAClass {
public:
    ArduinoOTAClass &setPort(uint16_t port);
    ArduinoOTAClass &setHostname(const char *hostname);
    ArduinoOTAClass &setPassword(const char *password);
    ArduinoOTAClass &setPasswordHash(const char *password);
    ArduinoOTAClass &onStart(void (*fn)(void));
    ArduinoOTAClass &onEnd(void (*fn)(void));
    void begin();
    void handle();
    void end();
};
extern ArduinoOTAClass ArduinoOTA;
