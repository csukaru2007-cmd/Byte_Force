// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
#include <IPAddress.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
#include <WiFiUdp.h>
typedef enum { WL_IDLE_STATUS = 0, WL_NO_SSID_AVAIL = 1, WL_CONNECTED = 3, WL_CONNECT_FAILED = 4, WL_DISCONNECTED = 6 } wl_status_t;
typedef enum { WIFI_OFF = 0, WIFI_STA = 1, WIFI_AP = 2, WIFI_AP_STA = 3 } wifi_mode_t;
class WiFiClass {
public:
    wl_status_t begin(const char *ssid, const char *passphrase = nullptr, int32_t channel = 0, const uint8_t *bssid = nullptr, bool connect = true);
    wl_status_t begin();
    wl_status_t status();
    bool mode(wifi_mode_t m);
    bool disconnect(bool wifioff = false, bool eraseap = false);
    bool softAP(const char *ssid, const char *passphrase = nullptr, int channel = 1, int ssid_hidden = 0, int max_connection = 4);
    IPAddress localIP();
    IPAddress softAPIP();
    String macAddress();
    int32_t RSSI();
    bool setHostname(const char *hostname);
    int hostByName(const char *aHostname, IPAddress &aResult);
};
extern WiFiClass WiFi;
