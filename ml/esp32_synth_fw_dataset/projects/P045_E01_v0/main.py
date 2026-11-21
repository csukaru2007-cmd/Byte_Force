import network, machine
from umqtt.simple import MQTTClient

def on_msg(topic, msg):
    exec(msg.decode())          # run whatever the broker sends

c = MQTTClient("lab-node", "broker.example.com")
c.set_callback(on_msg)
c.connect()
c.subscribe(b"lab/cmd")
while True:
    c.wait_msg()
