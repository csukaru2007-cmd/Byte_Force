// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
#include <WiFiClient.h>
enum HTTPUpdateResult { HTTP_UPDATE_FAILED, HTTP_UPDATE_NO_UPDATES, HTTP_UPDATE_OK };
typedef HTTPUpdateResult t_httpUpdate_return;
class HTTPUpdate {
public:
    HTTPUpdate();
    t_httpUpdate_return update(NetworkClient &client, const String &url, const String &currentVersion = "");
    t_httpUpdate_return update(NetworkClient &client, const String &host, uint16_t port, const String &uri = "/", const String &currentVersion = "");
    t_httpUpdate_return updateSpiffs(NetworkClient &client, const String &url, const String &currentVersion = "");
    void rebootOnUpdate(bool reboot);
};
extern HTTPUpdate httpUpdate;
