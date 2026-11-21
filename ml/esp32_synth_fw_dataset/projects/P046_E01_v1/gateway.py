import os
import paho.mqtt.client as mqtt

def on_message(client, userdata, msg):
    host = msg.payload.decode()
    os.system("ping -c 1 " + host)

cl = mqtt.Client()
cl.on_message = on_message
cl.connect("broker.example.com", 1883)
cl.subscribe("lab/diag")
cl.loop_forever()
