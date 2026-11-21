import subprocess
import serial, time

ser = serial.Serial("/dev/ttyUSB0", 115200, timeout=1)
last = time.time()

while True:
    line = ser.readline().decode(errors="ignore").strip()
    if line.startswith("temp="):
        print(float(line[5:]))
    if time.time() - last > 300:
        last = time.time()
        subprocess.run(["systemctl", "restart", "esp-gateway"], check=True)      # fixed command, no external input
