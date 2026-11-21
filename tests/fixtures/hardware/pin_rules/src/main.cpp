#include <Arduino.h>
#include <WiFi.h>
#include <driver/gpio.h>

#define FLASH_CLK_PIN 6
int configuredPin = 5;              // not const: decided at run time

int pinFromConfig() { return configuredPin; }

void setup() {
  Serial.begin(115200);
  WiFi.begin("Lab", nullptr);
  pinMode(FLASH_CLK_PIN, OUTPUT);   // flash-connected
  pinMode(STATUS_LED, OUTPUT);      // GPIO12 strapping (MTDI)
  pinMode(20, OUTPUT);              // GPIO20 does not exist on ESP32
  pinMode(37, INPUT);               // chip pin, not a WROOM-32 module pin
  pinMode(pinFromConfig(), OUTPUT); // non-constant
  pinMode(35, INPUT_PULLUP);        // GPIO35 has no pull resistors
  dacWrite(4, 128);                 // GPIO4 has no DAC
  touchRead(26);                    // GPIO26 is not a touch pin
  gpio_set_direction(GPIO_NUM_39, GPIO_MODE_OUTPUT);
  pinMode(1, OUTPUT);               // UART0 TX while Serial is used
  pinMode(14, OUTPUT);              // JTAG MTMS
  attachInterrupt(36, nullptr, RISING);
}

void loop() {
  analogRead(25);                   // ADC2 while Wi-Fi is used
  analogRead(32);                   // ADC1: fine with Wi-Fi
  dacWrite(25, 10);                 // DAC_1: fine
  touchRead(4);                     // T0: fine
}
