#!/usr/bin/python3

import sys
import os
import optparse
import concurrent.futures
from collections import defaultdict
import xml.etree.ElementTree as ET
import re
import requests
import socket
import ipaddress

BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CLEAR = '\x1b[0m'

print(BLUE + "NXScan[2.2] by ARPSyndicate" + CLEAR)
print(YELLOW + "fast port scanning with fancy output" + CLEAR)

if len(sys.argv) < 2:
    print(RED + "[!] ./NXScan --help" + CLEAR)
    sys.exit()

else:
    parser = optparse.OptionParser()
    parser.add_option('-l', '--list', action="store",
                      dest="list", help="list of targets to enumerate/scan")
    parser.add_option('-v', '--verbose', action="store_true",
                      dest="verbose", help="enable logging", default=False)
    parser.add_option('-T', '--template', action="store", dest="template",
                      help="path to XSL template [default= ./nmap-bootstrap.xsl]", default="nmap-bootstrap.xsl")
    parser.add_option('-t', '--threads', action="store", dest="threads",
                      help="threads [maximum/default= 3]", default=3)
    parser.add_option('-o', '--output', action="store",
                      dest="output", help="directory for saving the results")
    parser.add_option('-r', '--retries', action="store", dest="retries",
                      help="number of times to enumerate [default= 1]", default=1)
    parser.add_option('--only-enumerate', action="store_false", dest="scan",
                      help="only enumerate open ports using naabu & shodan", default=True)
    parser.add_option('--only-finger', action="store_true", dest="finger",
                      help="only fingerprint services using nmap", default=False)
    parser.add_option('--only-scan', action="store_false",
                      dest="enumerate", help="only scan using nmap & shodan", default=True)
    parser.add_option('--only-shodan-enum', action="store_true",
                      dest="shodane", help="only enum using shodan", default=False)
    parser.add_option('--only-shodan-scan', action="store_true",
                      dest="shodans", help="only scan using shodan", default=False)
    parser.add_option('--ports', action="store", dest="ports",
                      help="100,1000,full [default=1000]", default="1000")
    parser.add_option('--nmap-param', action="store", dest="nmpara",
                      help="nmap parameters [default= -Pn -A -T5]", default="-Pn -A -T5")
    parser.add_option('--naabu-param', action="store", dest="napara",
                      help="naabu parameters [default= -rate 800 -timeout 2500 -stats -retries 2 -scan-all-ips -exclude-cdn]", default="-rate 800 -timeout 2500 -stats -retries 2 -scan-all-ips -exclude-cdn ")

inputs, args = parser.parse_args()
if not inputs.list:
    parser.error(RED + "[!] input not given" + CLEAR)
if not inputs.output:
    parser.error(RED + "[!] output directory not provided" + CLEAR)
list = str(inputs.list)
verbose = inputs.verbose
output = str(inputs.output)
threads = int(inputs.threads)
enum = inputs.enumerate
scan = inputs.scan
finger = inputs.finger
shodane = inputs.shodane
shodans = inputs.shodans
bundle_dir = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
template = os.path.abspath(os.path.join(bundle_dir,str(inputs.template)))
napara = "-top-ports {0} {1}".format(inputs.ports, inputs.napara)
nmpara = inputs.nmpara
retries = int(inputs.retries)

if finger or shodane or shodans:
    scan = False
    enum = False

if scan:
    shodans = True
if enum:
    shodane = True

if(os.path.exists(output) == False):
    os.system("mkdir {0}".format(output))

if(os.path.exists(list) == False or os.stat(list).st_size == 0):
    parser.error(RED + "[!] input doesn't exists" + CLEAR)

if threads > 3:
    threads = 3

shodansresult = []
def shodanScan(target):
    global shodansresult
    if verbose:
        print(GREEN + "[VERBOSE] started scanning {0}".format(target) + CLEAR)
    ipi = ""
    try:
        ipaddress.ip_address(target)
        ipi = target
    except ValueError:
        ipi = socket.gethostbyname(target)
    try:
        sdat = requests.get("https://internetdb.shodan.io/"+ipi).json()
    except:
        return
    shodansresult.append("{0} {1} {2} {3} {4} {5} {6}".format(target, sdat['ip'], sdat['ports'], sdat['cpes'], sdat['hostnames'], sdat['tags'], sdat['vulns']))
    print(BLUE + "[+] completed scanning {0}".format(target) + CLEAR)
    with open("{0}/shodan-scan.txt".format(output), "w") as f:
        f.writelines("%s\n" % line for line in shodansresult)

shodaneresult = []
def shodanEnum(target):
    global shodaneresult
    if verbose:
        print(GREEN + "[VERBOSE] started enumerating {0}".format(target) + CLEAR)
    ipi = ""
    try:
        ipaddress.ip_address(target)
        ipi = target
    except ValueError:
        ipi = socket.gethostbyname(target)
    try:
        sdat = requests.get("https://internetdb.shodan.io/"+ipi).json()
    except:
        return
    for port in sdat['ports']:
        shodaneresult.append("{0}:{1}".format(target, port))
    print(BLUE + "[+] completed enumerating {0}".format(target) + CLEAR)
    with open("{0}/shodan-enum.txt".format(output), "w") as f:
        f.writelines("%s\n" % line for line in shodaneresult)


def nmapScan(target):
    host = target.split(" ")[0]
    ports = target.split(" ")[1]
    if verbose:
        print(GREEN + "[VERBOSE] started scanning {0}".format(host) + CLEAR)
    os.system(
        "sudo nmap {3} -p {0} {1} -oX {2}/scan/{1}.xml > /dev/null".format(ports, host, output, nmpara))
    print(BLUE + "[+] completed scanning {0}".format(host) + CLEAR)


def nmapFinger(target):
    global output
    host = target.split(" ")[0]
    ports = target.split(" ")[1]
    if verbose:
        print(
            GREEN + "[VERBOSE] started fingerprinting {0}".format(host) + CLEAR)
    os.system(
        "sudo nmap -T5 -sS -Pn -p {0} {1} -oG {2}/finger/{1} > /dev/null".format(ports, host, output))
    with open("{0}/finger/{1}".format(output, host), "r") as f:
        data = f.read()
    match = re.search(r'[0-9]*/open/.*///', data, re.M | re.I)
    if match:
        services = str(match.group()).split(",")
        res = ""
        for service in services:
            meta = service.strip().split("/")
            out = "[{0}] {2}:{1}".format(meta[4], meta[0], host)
            res = res+out+"\n"
            print("[{0}] {2}:{1}".format(meta[4], meta[0], host))
        with open("{0}/finger/{1}.txt".format(output, host), "w") as f:
            f.write(res)
        f.close()


def generateTXT():
    files = set()
    for txts in os.listdir(output+"/finger/"):
        if txts.endswith('.txt'):
            files.add(os.path.join(output+"/finger/", txts))
    final = output+"/finger.txt"
    data = ""
    for txt in files:
        if txt.endswith('.txt'):
            with open(txt, "r") as f:
                data = data + f.read()
    file = open(final, "w")
    file.write(data)
    file.close()
    return


def mergeXML(xml, final):
    with open(final, mode='a', encoding='utf-8') as mergFile:
        with open(xml) as f:
            nMapXML = ET.parse(f)
            for host in nMapXML.findall('host'):
                cHost = ET.tostring(host, encoding='unicode', method='xml')
                mergFile.write(cHost)
                mergFile.flush()


def generateHTML():
    files = set()
    for xmls in os.listdir(output+"/scan/"):
        if xmls.endswith('.xml'):
            files.add(os.path.join(output+"/scan/", xmls))
    final = output+"/scan.xml"
    out = '<?xml version="1.0" encoding="UTF-8"?>'
    out += '<!DOCTYPE nmaprun>'
    out += '<nmaprun scanner="https://github.com/ARPSyndicate/NXScan">'
    file = open(final, "w")
    file.write(out)
    file.close()
    for xml in files:
        if xml.endswith('.xml'):
            mergeXML(xml, final)
    out = '<runstats><finished/></runstats></nmaprun>'
    file = open(final, "a")
    file.write(out)
    file.close()
    os.system("xsltproc -o {0} {1} {2}".format(output +
                                               "/scan.html", template, final))
    return

if shodane:
    print(YELLOW + "[*] enumerating using shodan" + CLEAR)
    with open(list) as f:
        domains = f.read().splitlines()
    ipas = []
    for doms in domains:
        try:
            ipaddress.ip_network(doms)
            ipas.extend([str(ip) for ip in ipaddress.IPv4Network(doms)])
        except ValueError:
            continue
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        try:
            executor.map(shodanEnum, domains)
        except(KeyboardInterrupt, SystemExit):
            print(RED + "[!] interrupted" + CLEAR)
            executor.shutdown(wait=False)
            sys.exit()
        try:
            executor.map(shodanEnum, ipas)
        except(KeyboardInterrupt, SystemExit):
            print(RED + "[!] interrupted" + CLEAR)
            executor.shutdown(wait=False)
            sys.exit()
    os.system("cat {0}/enum-syn-*.txt {0}/enum-con-*.txt {0}/shodan-enum.txt | sort -u > {0}/enum.txt".format(output))    
    
if shodans:
    print(YELLOW + "[*] scanning using shodan" + CLEAR)
    with open(list) as f:
        domains = f.read().splitlines()
    ipas = []
    for doms in domains:
        try:
            ipaddress.ip_network(doms)
            ipas.extend([str(ip) for ip in ipaddress.IPv4Network(doms)])
        except ValueError:
            continue
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        try:
            executor.map(shodanScan, domains)
        except(KeyboardInterrupt, SystemExit):
            print(RED + "[!] interrupted" + CLEAR)
            executor.shutdown(wait=False)
            sys.exit()
        try:
            executor.map(shodanScan, ipas)
        except(KeyboardInterrupt, SystemExit):
            print(RED + "[!] interrupted" + CLEAR)
            executor.shutdown(wait=False)
            sys.exit()


if enum:
    print(YELLOW + "[*] enumerating using naabu" + CLEAR)
    for i in range(0, retries):
        os.system(
            "sudo naabu -l {0} -s s -o {2}/enum-syn-{3}.txt {1}".format(list, napara, output, i))
        os.system(
            "sudo naabu -l {0} -s c -o {2}/enum-con-{3}.txt {1}".format(list, napara, output, i))
    os.system(
        "cat {0}/enum-syn-*.txt {0}/enum-con-*.txt {0}/shodan-enum.txt | sort -u > {0}/enum.txt".format(output))
    list = "{0}/enum.txt".format(output)


if finger:
    print(YELLOW + "[*] fingerprinting using nmap" + CLEAR)
    os.system("mkdir {0}/finger".format(output))
    with open(list) as f:
        domains = f.read().splitlines()
    maps = defaultdict(set)
    for i in domains:
        maps[i.split(':')[0]].add(i.split(':')[1])
    targets = []
    for i in maps.keys():
        targets.append(i+" " + ','.join(maps[i]))
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        try:
            executor.map(nmapFinger, targets)
        except(KeyboardInterrupt, SystemExit):
            print(RED + "[!] interrupted" + CLEAR)
            executor.shutdown(wait=False)
            sys.exit()
    generateTXT()

if scan:
    print(YELLOW + "[*] scanning using nmap" + CLEAR)
    os.system("mkdir {0}/scan".format(output))
    with open(list) as f:
        domains = f.read().splitlines()
    maps = defaultdict(set)
    for i in domains:
        maps[i.split(':')[0]].add(i.split(':')[1])
    targets = []
    for i in maps.keys():
        targets.append(i+" " + ','.join(maps[i]))
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        try:
            executor.map(nmapScan, targets)
        except(KeyboardInterrupt, SystemExit):
            print(RED + "[!] interrupted" + CLEAR)
            executor.shutdown(wait=False)
            sys.exit()
    generateHTML()

print(YELLOW + "[*] done" + CLEAR)
