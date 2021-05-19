#coding:utf-8
import nmap
import time
import peewee
import os
import threading
from multiprocessing import Pool,cpu_count

db = peewee.SqliteDatabase(os.getcwd()+ '/result/' + 'testscan.db',timeout=30)
class Xxx_Nmap_Port_info(peewee.Model):
    IP_Address = peewee.CharField(max_length=100, verbose_name="ip地址")
    Port_ID = peewee.CharField(max_length=30, verbose_name="端口号")
    Port_Name = peewee.CharField(max_length=100, verbose_name="端口名称")
    Port_State = peewee.CharField(max_length=50, verbose_name="端口状态")
    Port_Reason = peewee.CharField(max_length=200, verbose_name="端口推测原因")
    Port_product = peewee.CharField(max_length=100, verbose_name="使用产品")
    Port_version = peewee.CharField(max_length=100, verbose_name="产品版本")
    Port_Banner = peewee.CharField(max_length=10000, verbose_name="端口Banner")
    class Meta:
        database = db

class Xxx_Nmap_Host_Ports(peewee.Model):
    IP_Address = peewee.CharField(max_length=100, verbose_name="ip地址")
    Host_Ports = peewee.CharField(max_length=100000000, verbose_name="端口集合")
    class Meta:
        database = db

def scanFromNmap(ip):#Nmap扫描执行
    host_info = {}
    host_scan_start_time = time.asctime(time.localtime(time.time()))
    print(host_scan_start_time)
    print('%s:%s is Running   Scanning IP:%s ' %(threading.currentThread().getName(),os.getpid(),ip))
    nm = nmap.PortScanner()
    tmp = nm.scan(hosts = ip,arguments='-sV -Pn --host-timeout 500 -p 49665,49162,35793,2107,14498,27036,43889,55920,54870,9100,53048,9095,35065,49152,7051,3911,37763,52583,21158,59468,49154,54479,9093,8680,22,5555,10000,1021,62110,49674,43261,44089,34642,8058,49664,15513,7000,18533,44083,6093,20831,10243,999,912,54481,16080,39633,9001,46888,17981,49668,1094,1234,5900,10153,38073,111,43959,42587,631,45563,59898,49696,18860,49156,49277,49167,1801,20820,49278,515,61206,139,8080,53775,45655,10097,2869,49670,58412,31877,9000,35165,58447,3910,50696,32109,443,2103,19487,40293,13220,445,5091,3306,808,44545,55555,48432,3283,22471,57871,554,54480,34581,65527,49199,51575,10136,2179,49155,15398,17529,52266,43111,49666,20140,2049,6095,49161,46839,35673,49157,11396,9888,49652,52288,4466,5357,7100,53929,30102,49194,59866,44987,12779,8291,1017,33549,53211,49667,49196,42621,7981,6087,902,48440,8289,1029,6780,10566,45869,45233,6646,62078,6503,49153,2105,55613,18023,7070,8701,88,51180,1023,49672,8000,61593,7680,51688,8295,6091,36157,65417,51124,42897,55364,41593,37583,42103,28122,23,61323,5005,54921,8081,135,7890,58902,49673,80,62970,28130,5040,33971,5786,28201,3389,54482')
    print(tmp)
    if len(tmp['scan']) == 0:
        print("[!][%s] 主机不存活"%ip)
    elif ('tcp' in tmp['scan'][ip]):
        host_info = tmp['scan'][ip]['tcp']
    else:
        print("[!][%s] 未探测到TCP端口"%ip)
    getHostPortInfo(ip, host_info)
    print("[%s] Nmap扫描已完成"%ip)

def getHostPortInfo(ip,host_info): #u'获取IP所有端口的 service banner state并写入数据库'
    host_ports = []
    if bool(host_info):
        for port,port_value in host_info.items():
            port_info = {
                'ip':ip,
                'port':str(port),
                'name':port_value['name'],
                'product':port_value['product'],
                'version':port_value['version'],
                'reason':port_value['reason'],
                'state':port_value['state'],
            }
            if ('script' in port_value):
                if ('banner' in port_value['script']):
                    port_info['banner'] = port_value['script']['banner']
                else:
                    port_info['banner'] = ''
            else:
                port_info['banner'] = ''
            if port_info['state'] == 'open':
                host_ports.append(port)
            #u'将pid ip port service banner state信息写入Port_info表中'
            k = Xxx_Nmap_Port_info().insert(
                IP_Address=port_info['ip'],
                Port_ID=port_info['port'],
                Port_Name=port_info['name'],
                Port_State=port_info['state'],
                Port_Reason=port_info['reason'],
                Port_product=port_info['product'],
                Port_version=port_info['version'],
                Port_Banner=port_info['banner'],
            )
            k.execute()
        #u'将有端口信息的id ip ports信息写入Host_Ports表中'
        k = Xxx_Nmap_Host_Ports.insert(
            IP_Address=ip,
            Host_Ports=host_ports,
        )
        k.execute()
    else:
        #u'将没有端口信息的id ip ports信息写入Host_Ports表中'
        k = Xxx_Nmap_Host_Ports.insert(
            IP_Address=ip,
            Host_Ports='[]',
        )
        k.execute()
    print("[%s] 已经完成写入数据库" %ip)

if __name__ == '__main__':
    start_time = time.time()
    hosts = []
    Xxx_Nmap_Host_Ports.create_table()
    Xxx_Nmap_Port_info.create_table()
    with open('ip_list.txt', 'r') as f:
        for i in f:
            hosts.append(i.strip())
    px = Pool(cpu_count())
    for i in hosts:
        px.apply_async(scanFromNmap,(i,))
    px.close()
    px.join()
    print (time.time() - start_time)









