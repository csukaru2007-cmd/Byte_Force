CONFIG_EXPR = "[34, 35, 32][1]"
from machine import ADC, Pin
pin_no = eval(CONFIG_EXPR)           # constant expression evaluated at runtime
print(ADC(Pin(pin_no)).read())
