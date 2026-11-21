LIMIT = 30
exec("threshold = %d" % LIMIT)       # exec used to set a variable
from machine import ADC, Pin
a = ADC(Pin(34))
while True:
    if a.read() > threshold * 10:
        print("high")
