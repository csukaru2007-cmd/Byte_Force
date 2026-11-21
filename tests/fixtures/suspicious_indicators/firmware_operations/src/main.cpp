#include <Arduino.h>
#include <ArduinoOTA.h>
#include <HTTPUpdate.h>
#include <WiFiClientSecure.h>
#include <esp_flash.h>
#include <esp_efuse.h>
#include <esp_ota_ops.h>

extern const esp_efuse_desc_t *SOME_EFUSE_FIELD[];

void setup() {
  ArduinoOTA.begin();                                     // no password set
  WiFiClientSecure insecureClient;
  insecureClient.setInsecure();                           // TLS verification disabled
  httpUpdate.update(insecureClient, "http://updates.example.com/fw.bin");   // plain HTTP
}

void maintenance() {
  esp_flash_erase_region(esp_flash_default_chip, 0x10000, 0x1000);
  esp_efuse_write_field_bit(SOME_EFUSE_FIELD);            // permanent
  esp_ota_set_boot_partition(esp_ota_get_next_update_partition(nullptr));
}

void loop() { ArduinoOTA.handle(); }
