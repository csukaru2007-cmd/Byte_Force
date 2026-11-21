from machine import ADC, Pin
adc = ADC(Pin(34))

while True:
    t = adc.read() * 0.08
    f = eval("%f * 1.8 + 32" % t)     # eval for a trivial conversion
    print(f)
