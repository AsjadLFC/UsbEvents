import pyudev
import json
import socket
import splunklib.client as client
from time import strftime
from datetime import datetime

# USB detection settings
context = pyudev.Context()
monitor = pyudev.Monitor.from_netlink(context)
monitor.filter_by(subsystem='usb')

# Splunk socket settings
HOST = "" 
USERNAME = ""
PASSWORD = ""

# Name of the machine
HOSTNAME = socket.gethostname()

# Connection to splunk
service = client.connect(
    host = HOST,
    username = USERNAME,
    password = PASSWORD
)

index = service.indexes["prevent"]

# Sending JSON on 'add' and 'remove' events on the USB
for device in iter(monitor.poll, None):
    with index.attached_socket(sourcetype='_json', host = HOSTNAME) as sock:
        if device.action == 'add':
            jsonData = {
                "type": "USBDetection",
                "status": "True",
                "lastHeartbeatTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lastTransitionTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "reason": "USBDeviceDetected",
                "message": "USB device plugged in"
            }
            sock.send(json.dumps(jsonData, indent = 4, sort_keys = True))
        elif device.action == 'remove':
            jsonData = {
                "type": "USBDetection",
                "status": "False",
                "lastHeartbeatTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lastTransitionTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "reason": "NoUSBDeviceDetected",
                "message": "USB device plugged out"
            }
            sock.send(json.dumps(jsonData, indent=4, sort_keys=True))
            
service.logout()
