#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Nov 23 18:11:10 2022

@author: robin
"""

from scapy.all import *

def handler(packet):
    #간단한 요약정보로 출력
    print(packet.summary())
    #print(packet.show())

def sniffICMP(): 
    #srp(prn=handler,filter="icmp", iface=None, timeout=2)
    pkt = sniff(prn=handler, filter="icmp", timeout =15)
    for packet in pkt:
        if  str(packet.getlayer(ICMP).type) == "3":
            print ("Destination Unreachable")
            print(packet[IP].src)
        if str(packet.getlayer(ICMP).type) == "8":
    
            print("ip" + packet[IP].src)
def main():
    #패킷 덤프
 
    sniffICMP()
main()