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
    cmd = ["masscan", "-p0-65535,U:0-65535" , HOST, "--rate=500", "-e", INTERFACE]
    output = run_shell(cmd)
    masscan_ports = re.findall('port (\d*)', output)
    nmap(HOST,masscan_ports)
    return

def nmap(HOST,masscan_ports):
    ports = list({int(port) for port in masscan_ports})
    print(ports.sort())
    if masscan_ports:
        cmd = ["nmap","-Pn","-sC","-sV","-T4","-v","-p"+''.join(str(ports)[1:-1].split()), HOST]
        run_shell(cmd)
    return

if __name__=="__main__":
    if len(sys.argv) < 3:
        print("[+] pscan performs a full TCP/UDP port scan against the supplied host")
        print("[*] Usage: " + sys.argv[0] +" <Target-HOST>" + " <Target-Network-Interface>")
        exit(1)
    HOST = sys.argv[1]
    INTERFACE = sys.argv[2]
    
    start = time.clock()
    #print(start)
    masscan(HOST,INTERFACE)
    #print("[+] Completed scan in " + str(time.clock()-start) + " min")
    #print(time.clock())
