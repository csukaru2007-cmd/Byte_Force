// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
#include <WiFi.h>
class WebServer {
public:
    WebServer(int port = 80);
    void begin();
    void handleClient();
    void on(const char *uri, void (*handler)(void));
    String arg(const char *name);
    String arg(int i);
    bool hasArg(const char *name);
    void send(int code, const char *content_type = nullptr, const String &content = String(""));
    bool authenticate(const char *username, const char *password);
};
