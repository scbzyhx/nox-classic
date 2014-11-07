#! /usr/bin/env python
#
#This is aimed at copying with routing tables from json files and updates into json files
#
from nox.lib.packet.packet_utils import ipstr_to_int,ip_to_str
import json
import os
import os.path
import shutil
import time,datetime


def ascii_encode_dict(data):
    ascii_encode = lambda x: x.encode('ascii') if (type(x) ==type(u'a')) else x
    return dict(map(ascii_encode,pair) for pair in data.items())

def getCurTime():
    nowTime = time.localtime()
    year = str(nowTime.tm_year)
    month = str(nowTime.tm_mon)
    if len(month) < 2:
        month = '0'+ month
    day = str(nowTime.tm_yday)
    if len(day) < 2:
        day = '0'+day

    return (year + '_' + month + '_' + day)

def bakFile(f):
    shutil.copyfile(f,f+getCurTime())

GATEWAY = "gateway"
COUNTER = 'count'
DEFAULT = 'default'

class Table:
    'This is static routing table'
    def __init__(self,config='table.json'):
        with open(config) as f:
            jsonData = f.read()
            self.table = json.loads(jsonData,encoding='ascii',object_hook=ascii_encode_dict)

    def updateCount(self,ip,inc = 1):
        ipstr = ip_to_str(ip) ##convert to IPstr
        try:
            self.table[ipstr][COUNTER] += inc
            return True
        except KeyError as e:
            #log 
            return False
    def getRoute(self,ip):
        ipstr = ip_to_str(ip)

        try:
            result = self.table[ipstr]
            return (result[GATEWAY],result[COUNTER])

        except KeyError as e:
            return None
    def storeRouteTable(self,config='table.json'):
        if os.path.exists(config) and os.path.isfile(config):
            'bake up previous file'
            bakfile(config)

        with open(config,'w') as f:
            f.write(json.dumps(self.table))
    def getDefaultRoute(self):
        return (self.table[DEFAULT][GATEWAY],self.table[DEFAULT][COUNTER])

    def __str__(self):
        return str(self.table)
