// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <WiFiClient.h>
class WiFiClientSecure : public WiFiClient {
public:
    WiFiClientSecure();
    void setInsecure();
    void setCACert(const char *rootCA);
    void setCertificate(const char *client_ca);
    void setPrivateKey(const char *private_key);
    void setPreSharedKey(const char *pskIdent, const char *psKey);
};
