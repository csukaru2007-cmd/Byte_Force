import subprocess
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
