#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFiClientSecure.h>
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"

const char* NET_SSID = "YOUR_SSID";
const char* NET_PW = "YOUR_PASSWORD";
const char* FW_URL = "https://fw.example.com/fw/esp32-node-18/firmware.bin";
const char* SIG_URL = "https://fw.example.com/fw/esp32-node-18/firmware.sig";
const char* ROOT_CA = "-----BEGIN CERTIFICATE-----\n<PLACEHOLDER_ROOT_CA>\n-----END CERTIFICATE-----\n";
const char* EXPECTED_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000";


bool hashMatches(const uint8_t* digest, const String& expectedHex) {
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", digest[i]);
  hex[64] = 0;
  return expectedHex.equalsIgnoreCase(String(hex));
}

static const char PUBKEY_PEM[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "<PLACEHOLDER_BASE64_PUBLIC_KEY>\n"
  "-----END PUBLIC KEY-----\n";

bool verifySignature(const uint8_t* digest, const uint8_t* sig, size_t sigLen) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int rc = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)PUBKEY_PEM, sizeof(PUBKEY_PEM));
  if (rc == 0) rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, 32, sig, sigLen);
  mbedtls_pk_free(&pk);
  return rc == 0;
}

bool httpGetString(const char* URL, String& out) {
  HTTPClient http;
  WiFiClientSecure client;
  client.setCACert(ROOT_CA);
  http.begin(client, URL);
  int code = http.GET();
  if (code != 200) { http.end(); return false; }
  out = http.getString();
  http.end();
  return true;
}

size_t fetchBinary(const char* URL, uint8_t* buf, size_t cap) {
  HTTPClient http;
  WiFiClientSecure client;
  client.setCACert(ROOT_CA);
  http.begin(client, URL);
  int code = http.GET();
  if (code != 200) { http.end(); return 0; }
  size_t n = http.getStreamPtr()->readBytes(buf, cap);
  http.end();
  return n;
}

bool performUpdate() {
  String expectedSha = EXPECTED_SHA256;
  uint8_t sig[256];
  size_t sigLen = fetchBinary(SIG_URL, sig, sizeof(sig));
  if (sigLen == 0) return false;
  const char* URL = FW_URL;
  HTTPClient http;
  WiFiClientSecure client;
  client.setCACert(ROOT_CA);
  http.begin(client, URL);
  int code = http.GET();
  if (code != 200) { http.end(); return false; }
  int len = http.getSize();
  if (!Update.begin(len > 0 ? len : UPDATE_SIZE_UNKNOWN)) { http.end(); return false; }
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  WiFiClient* s = http.getStreamPtr();
  uint8_t buf[1024];
  int remaining = len;
  while (http.connected() && remaining > 0) {
    size_t n = s->readBytes(buf, min(remaining, 1024));
    if (n == 0) break;
    Update.write(buf, n);
    mbedtls_sha256_update(&ctx, buf, n);
    remaining -= n;
  }
  http.end();
  uint8_t digest[32];
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);
  if (!hashMatches(digest, expectedSha)) { Update.abort(); return false; }
  if (!verifySignature(digest, sig, sigLen)) { Update.abort(); return false; }
  return Update.end(true);
}


void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
    WiFi.begin(NET_SSID, NET_PW);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  if (performUpdate()) { Serial.println("Update OK"); ESP.restart(); }
  else Serial.println("Update rejected");
}

void loop() {
  static unsigned long last = 0;
  if (millis() - last > 2000) { last = millis(); Serial.println("heartbeat"); }
}
