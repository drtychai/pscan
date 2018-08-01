#!/usr/bin/python3
import subprocess
import os, signal
import sys, re
import time

def run_shell(cmd):
    print("\n[+] Running command: "+' '.join(cmd))
    sp = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ""
    while True:
        out = sp.stdout.read(1).decode('utf-8')
        if out == '' and sp.poll() != None:
            break
        if out != '':
            output += out
            sys.stdout.write(out)
            sys.stdout.flush()
        # set breakpoint for masscan bug [144]
        if "0.00-kpps, 100.00% done" in output:
            break
    return output

def masscan(HOST,INTERFACE):
    cmd = ["masscan", "-p0-65535,U:0-65535" , HOST, "--rate=1000", "-e", INTERFACE]
    output = run_shell(cmd)
    tcp_ports = re.findall('port (\d*)/tcp', output)
    udp_ports = re.findall('port (\d*)/udp', output)
    nmap(HOST,tcp_ports,udp_ports)
    return

def nmap(HOST,tcp_ports,udp_ports):
    tports = list({int(tports) for tports in tcp_ports})
    uports = list({int(uports) for uports in udp_ports})
    if tcp_ports and udp_ports:
        cmd = ["nmap","-Pn","-sC","-sV","-sS","-sU","-T4","-p T:"+''.join(str(tports)[1:-1].split())+",U:"+''.join(str(uports)[1:-1].split()),HOST] 
    elif tcp_ports:
        cmd = ["nmap","-Pn","-sC","-sV","-T4","-p "+''.join(str(tports)[1:-1].split()), HOST]
    elif udp_ports:
        cmd = ["nmap","-Pn","-sC","-sV","-sU","-T4","-p "+''.join(str(uports)[1:-1].split()), HOST]
    run_shell(cmd)
    return

if __name__=="__main__":
    if len(sys.argv) < 3:
        print("[+] pscan performs a full TCP/UDP port scan against the supplied host")
        print("[*] Usage: " + sys.argv[0] +" <Target-HOST>" + " <Target-Network-Interface>")
        exit(1)
    HOST = sys.argv[1]
    INTERFACE = sys.argv[2] 
    masscan(HOST,INTERFACE)
