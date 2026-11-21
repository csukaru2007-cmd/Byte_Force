#include <WiFi.h>
#include <WebServer.h>
#include <Update.h>

const char* ssid = "YOUR_SSID";
const char* password = "YOUR_PASSWORD";
WebServer server(80);


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

void setup() {
  Serial.begin(921600);
  WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(WiFi.localIP());
  server.on("/update", HTTP_POST, []() {
    server.sendHeader("Connection", "close");
    server.send(200, "text/plain", Update.hasError() ? "FAIL" : "OK");
    delay(500);
    ESP.restart();
  }, handleUpload);
  server.begin();
}

void loop() {
  server.handleClient();
}
