from machine import ADC, Pin
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
