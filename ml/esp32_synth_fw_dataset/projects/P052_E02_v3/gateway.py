import os
import serial, time

ser = serial.Serial("/dev/ttyUSB0", 115200, timeout=1)
last = time.time()

while True:
    line = ser.readline().decode(errors="ignore").strip()
    if line.startswith("temp="):
        print(float(line[5:]))
    if time.time() - last > 600:
        last = time.time()
        os.system("date -u > /var/log/esp_gw_last_sync")      # fixed command, no external input
