import serial, csv

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
