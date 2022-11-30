#!/usr/bin/env python3
#-*- coding:utf-8 -*-

import queue

quick_view_queue=queue.Queue()  #라벨
detail_view_queue=queue.Queue() #패킷
filter_queue=queue.Queue(maxsize=1) #필터
packet_to_filter=queue.Queue(maxsize=1) #쓰레드 파일용 필터



def get_pkt():
    return detail_view_queue

def get_label():
    return quick_view_queue

def get_filter():
    return filter_queue

def get_packet_to_filter():
    return packet_to_filter

