// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
#include <Client.h>
class PubSubClient {
public:
    PubSubClient();
    PubSubClient(Client &client);
    PubSubClient &setServer(const char *domain, uint16_t port);
    PubSubClient &setServer(IPAddress ip, uint16_t port);
    PubSubClient &setClient(Client &client);
    PubSubClient &setCallback(void (*callback)(char *, uint8_t *, unsigned int));
    bool connect(const char *id);
    bool connect(const char *id, const char *user, const char *pass);
    void disconnect();
    bool publish(const char *topic, const char *payload);
    bool publish(const char *topic, const uint8_t *payload, unsigned int plength);
    bool subscribe(const char *topic);
    bool loop();
    bool connected();
};
