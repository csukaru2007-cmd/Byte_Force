// ShipSafe analysis stub: declarations only, used when the real Arduino-ESP32 headers
// are unavailable. Constant values are copied from espressif/arduino-esp32:
//   cores/esp32/esp32-hal-gpio.h   (LOW/HIGH, pin modes, interrupt modes)
//   variants/esp32/pins_arduino.h  (TX, RX, SDA, SCL, SPI pins, A*, T*, DAC*)
// The generic esp32 variant defines no LED_BUILTIN, so none is declared here.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#define ARDUINO_STUB_SHIPSAFE 1

// esp32-hal-gpio.h
#define LOW  0x0
#define HIGH 0x1
#define INPUT 0x01
#define OUTPUT            0x03
#define PULLUP            0x04
#define INPUT_PULLUP      0x05
#define PULLDOWN          0x08
#define INPUT_PULLDOWN    0x09
#define OPEN_DRAIN        0x10
#define OUTPUT_OPEN_DRAIN 0x13
#define ANALOG            0xC0
#define DISABLED  0x00
#define RISING    0x01
#define FALLING   0x02
#define CHANGE    0x03
#define ONLOW     0x04
#define ONHIGH    0x05
#define digitalPinToInterrupt(p) (p)

// variants/esp32/pins_arduino.h
static const uint8_t TX = 1;
static const uint8_t RX = 3;
static const uint8_t SDA = 21;
static const uint8_t SCL = 22;
static const uint8_t SS = 5;
static const uint8_t MOSI = 23;
static const uint8_t MISO = 19;
static const uint8_t SCK = 18;
static const uint8_t A0 = 36;
static const uint8_t A3 = 39;
static const uint8_t A4 = 32;
static const uint8_t A5 = 33;
static const uint8_t A6 = 34;
static const uint8_t A7 = 35;
static const uint8_t A10 = 4;
static const uint8_t A11 = 0;
static const uint8_t A12 = 2;
static const uint8_t A13 = 15;
static const uint8_t A14 = 13;
static const uint8_t A15 = 12;
static const uint8_t A16 = 14;
static const uint8_t A17 = 27;
static const uint8_t A18 = 25;
static const uint8_t A19 = 26;
static const uint8_t T0 = 4;
static const uint8_t T1 = 0;
static const uint8_t T2 = 2;
static const uint8_t T3 = 15;
static const uint8_t T4 = 13;
static const uint8_t T5 = 12;
static const uint8_t T6 = 14;
static const uint8_t T7 = 27;
static const uint8_t T8 = 33;
static const uint8_t T9 = 32;
static const uint8_t DAC1 = 25;
static const uint8_t DAC2 = 26;

typedef bool boolean;
typedef uint8_t byte;
typedef uint16_t word;

void pinMode(uint8_t pin, uint8_t mode);
void digitalWrite(uint8_t pin, uint8_t val);
int digitalRead(uint8_t pin);
uint16_t analogRead(uint8_t pin);
uint32_t analogReadMilliVolts(uint8_t pin);
void analogWrite(uint8_t pin, int value);
void analogReadResolution(uint8_t bits);
void dacWrite(uint8_t pin, uint8_t value);
uint16_t touchRead(uint8_t pin);
void attachInterrupt(uint8_t pin, void (*)(void), int mode);
void detachInterrupt(uint8_t pin);
// LEDC (arduino-esp32 2.x and 3.x APIs)
uint32_t ledcSetup(uint8_t channel, uint32_t freq, uint8_t resolution_bits);
void ledcAttachPin(uint8_t pin, uint8_t channel);
bool ledcAttach(uint8_t pin, uint32_t freq, uint8_t resolution);
bool ledcAttachChannel(uint8_t pin, uint32_t freq, uint8_t resolution, uint8_t channel);
void ledcWrite(uint8_t chan_or_pin, uint32_t duty);

void delay(uint32_t ms);
void delayMicroseconds(uint32_t us);
unsigned long millis(void);
unsigned long micros(void);
long random(long max);
long random(long min, long max);
void randomSeed(unsigned long seed);
long map(long x, long in_min, long in_max, long out_min, long out_max);
template <class T> T min(T a, T b);
template <class T> T max(T a, T b);
template <class T> T constrain(T x, T a, T b);
int log_printf(const char *fmt, ...);
#define log_e(format, ...) log_printf(format, ##__VA_ARGS__)
#define log_w(format, ...) log_printf(format, ##__VA_ARGS__)
#define log_i(format, ...) log_printf(format, ##__VA_ARGS__)
#define log_d(format, ...) log_printf(format, ##__VA_ARGS__)
#define F(s) (s)
#define PROGMEM

class __FlashStringHelper;

class String {
public:
    String(const char *cstr = "");
    String(const String &str);
    String(char c);
    String(int value, unsigned char base = 10);
    String(unsigned int value, unsigned char base = 10);
    String(long value, unsigned char base = 10);
    String(unsigned long value, unsigned char base = 10);
    String(float value, unsigned char decimalPlaces = 2);
    String(double value, unsigned char decimalPlaces = 2);
    String &operator=(const String &rhs);
    String &operator=(const char *cstr);
    String &operator+=(const String &rhs);
    String &operator+=(const char *cstr);
    bool operator==(const String &rhs) const;
    bool operator==(const char *cstr) const;
    char operator[](unsigned int index) const;
    const char *c_str() const;
    unsigned int length() const;
    int toInt() const;
    float toFloat() const;
    int indexOf(const char *s) const;
    String substring(unsigned int beginIndex, unsigned int endIndex) const;
    bool startsWith(const String &prefix) const;
    void trim();
    void getBytes(unsigned char *buf, unsigned int bufsize) const;
};
String operator+(const String &lhs, const String &rhs);
String operator+(const String &lhs, const char *rhs);
String operator+(const char *lhs, const String &rhs);

class Print {
public:
    virtual size_t write(uint8_t) = 0;
    virtual size_t write(const uint8_t *buffer, size_t size);
    size_t write(const char *str);
    size_t print(const char[]);
    size_t print(const String &);
    size_t print(char);
    size_t print(int, int = 10);
    size_t print(unsigned int, int = 10);
    size_t print(long, int = 10);
    size_t print(unsigned long, int = 10);
    size_t print(double, int = 2);
    size_t println(const char[]);
    size_t println(const String &);
    size_t println(char);
    size_t println(int, int = 10);
    size_t println(unsigned int, int = 10);
    size_t println(long, int = 10);
    size_t println(unsigned long, int = 10);
    size_t println(double, int = 2);
    size_t println(void);
    size_t printf(const char *format, ...);
};

class Stream : public Print {
public:
    virtual int available() = 0;
    virtual int read() = 0;
    virtual int peek() = 0;
    size_t readBytes(char *buffer, size_t length);
    size_t readBytes(uint8_t *buffer, size_t length);
    String readString();
    String readStringUntil(char terminator);
    void setTimeout(unsigned long timeout);
};

#define SERIAL_8N1 0x800001c
class HardwareSerial : public Stream {
public:
    HardwareSerial(uint8_t uart_nr);
    void begin(unsigned long baud, uint32_t config = SERIAL_8N1, int8_t rxPin = -1, int8_t txPin = -1,
               bool invert = false, unsigned long timeout_ms = 20000UL);
    bool setPins(int8_t rxPin, int8_t txPin, int8_t ctsPin = -1, int8_t rtsPin = -1);
    void end();
    int available();
    int read();
    int peek();
    size_t write(uint8_t);
    size_t write(const uint8_t *buffer, size_t size);
};
extern HardwareSerial Serial;
extern HardwareSerial Serial1;
extern HardwareSerial Serial2;

class EspClass {
public:
    void restart();
    uint32_t getFreeHeap();
    uint32_t getFlashChipSize();
    const char *getChipModel();
    uint64_t getEfuseMac();
    bool flashEraseSector(uint32_t sector);
    bool flashWrite(uint32_t offset, uint32_t *data, size_t size);
    bool flashRead(uint32_t offset, uint32_t *data, size_t size);
    bool partitionEraseRange(const void *partition, uint32_t offset, size_t size);
    bool partitionWrite(const void *partition, uint32_t offset, uint32_t *data, size_t size);
};
extern EspClass ESP;

void setup(void);
void loop(void);
