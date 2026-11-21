// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
class Preferences {
public:
    bool begin(const char *name, bool readOnly = false, const char *partition_label = nullptr);
    void end();
    bool clear();
    bool remove(const char *key);
    size_t putString(const char *key, const char *value);
    size_t putString(const char *key, String value);
    String getString(const char *key, String defaultValue = String());
    size_t getString(const char *key, char *value, size_t maxLen);
    size_t putUInt(const char *key, uint32_t value);
    uint32_t getUInt(const char *key, uint32_t defaultValue = 0);
    size_t putBool(const char *key, bool value);
    bool getBool(const char *key, bool defaultValue = false);
    size_t putBytes(const char *key, const void *value, size_t len);
    size_t getBytes(const char *key, void *buf, size_t maxLen);
};
