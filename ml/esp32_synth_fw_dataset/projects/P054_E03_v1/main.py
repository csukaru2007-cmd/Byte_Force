from machine import ADC, Pin

def read_temp(): return ADC(Pin(34)).read() * 0.08
def read_hum():  return ADC(Pin(35)).read() * 0.02

for name in ("temp", "hum"):
    print(name, globals()["read_" + name]())    # dynamic lookup of fixed names
