// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
#include <WiFiClient.h>
#define HTTP_CODE_OK 200
class HTTPClient {
public:
    HTTPClient();
    bool begin(String url);
    bool begin(String url, const char *CAcert);
    bool begin(NetworkClient &client, String url);
    bool begin(NetworkClient &client, String host, uint16_t port, String uri = "/", bool https = false);
    bool begin(String host, uint16_t port, String uri = "/");
    void end();
    int GET();
    int PATCH(uint8_t *payload, size_t size);
    int PATCH(String payload);
    int POST(uint8_t *payload, size_t size);
    int POST(String payload);
    int PUT(uint8_t *payload, size_t size);
    int PUT(String payload);
    int sendRequest(const char *type, String payload);
    int sendRequest(const char *type, uint8_t *payload = nullptr, size_t size = 0);
    void addHeader(const String &name, const String &value, bool first = false, bool replace = true);
    void setAuthorization(const char *user, const char *password);
    void setAuthorization(const char *auth);
    void setUserAgent(const String &userAgent);
    String getString();
    NetworkClient &getStream();
    NetworkClient *getStreamPtr();
    int getSize();
    int writeToStream(Stream *stream);
};
