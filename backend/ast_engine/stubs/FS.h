// ShipSafe analysis stub: declarations only, used when real headers are unavailable.
#pragma once
#include <Arduino.h>
namespace fs {
class File : public Stream {
public:
    size_t write(uint8_t);
    size_t write(const uint8_t *buf, size_t size);
    int available();
    int read();
    int peek();
    size_t size() const;
    void close();
    operator bool() const;
};
class FS {
public:
    File open(const char *path, const char *mode = "r", bool create = false);
    bool exists(const char *path);
    bool remove(const char *path);
};
}
using fs::File;
using fs::FS;
