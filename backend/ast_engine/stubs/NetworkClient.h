// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Client.h>
class NetworkClient : public Client {
public:
    NetworkClient();
    int connect(IPAddress ip, uint16_t port);
    int connect(const char *host, uint16_t port);
    int connect(const char *host, uint16_t port, int32_t timeout_ms);
    size_t write(uint8_t data);
    size_t write(const uint8_t *buf, size_t size);
    int available();
    int read();
    int read(uint8_t *buf, size_t size);
    int peek();
    void flush();
    void stop();
    uint8_t connected();
    IPAddress remoteIP();
};
