import nsq
import time
import ssl
import json
import frida
import time
import socket
import ppadb
import hashlib
from ppadb.client import Client as AdbClient
import urllib.request

def on_message(message, data):
    if message['type'] == 'send':
        sha = hashlib.sha1(data).hexdigest()
        print('[*] {0} received!'.format(sha))
        fd = open("/data/assets/%s/%s" % (task, sha), 'w')
        fd.write(data)
        fd.close()
    else:
        print(message)

def install(device, file):
    try:
        print("Attempting install of %s" % file)
        device.install(file)
    except ppadb.InstallError as e:
        print("Error installing : ", e)
        if "INSTALL_FAILED_ALREADY_EXISTS" not in str(e):
            return False
    return True

def uninstall(device, package_name):
    print("Attempting uninstall of %s" % package_name)
    device.uninstall(package_name)
    return True

def unpack(package_name, device_serial):
    scriptname = '/scripts/unpack.js'
    fd = open(scriptname, 'r')
    dm = frida.get_device_manager()
    device = dm.get_device(device_serial)
    pid = device.spawn([package_name])
    session = device.attach(pid)
    script = session.create_script(fd.read())
    fd.close()
    script.on('message', on_message)
    print("About to load script")
    script.load()
    print("Script loaded")
    device.resume(pid)
    print("Resumed pid")
    # sys.stdin.read()
    return True

def initialize_frida(device):
    ret = device.shell("stat /data/local/tmp/frida-server")
    if "No such file or directory" in ret:
        device.push("frida-server", "/data/local/tmp/frida-server")
        device.shell("chmod +x /data/local/tmp/frida-server")
    
    ret = device.shell("netstat -ntlp | grep frida")
    if "frida-server" not in ret:
        device.shell("/data/local/tmp/frida-server -D")
        

def get_device(proxy_port):
    client = AdbClient(host="localhost", port=5037)
    if client.remote_connect("backend", proxy_port):
        device = client.devices()[0]
        print("Using device : %s" % device.serial)
        waiting = True
        while waiting:
            try:
                whoami = device.shell('whoami')
                # This will always be root on an eng build
                if 'root' not in whoami:
                    print("Unlikely this will work... : %s" % whoami)
                else:
                    waiting = False
            except Exception as e:
                print("Hit exception waiting, will retry in 1 second... ", e)
                time.sleep(1)
        return device

def handler(msg):
    parsed = json.loads(msg.body)
    print("I've just now parsed: ")
    print(parsed)
    
    task = parsed['file_path'].split("/")[3]

    device = get_device(parsed['port'])
    initialize_frida(device)
    print("Frida initialized and should be running")

    install(device, parsed['file_path'])
    print("Installed!")
    
    print("Unpacking")
    unpack(parsed['package_name'], "backend:%d" % parsed['port'])
    print("unpacked")

    uninstall(device, parsed['package_name'])
    print("Uninstalled!")
    return True

task = ""

if __name__ == '__main__':
    print('Running running')

    alive = False
    while not alive:
        try:
            contents = urllib.request.urlopen("http://backend:3000/health").read()
            if contents == b'OK':
                alive = True
            else:
                print("Got unexpected answer from backend, will retry : %s" % contents)
                time.sleep(1)
        except urllib.error.URLError:
            print("Waiting for backend to come alive...")
            time.sleep(1)

    reader = nsq.Reader(message_handler=handler,
            nsqd_tcp_addresses=['nsqd:4150'],
            topic='unpack_tasks', channel='test', lookupd_poll_interval=15,
            user_agent='pyworker')
    nsq.run()