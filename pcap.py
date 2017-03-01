from scapy.all import rdpcap
import logging, math, subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from Tkinter import *

SENT = 1
RECEIVED = 2
BUCKET_SIZE = 0.1
def get_ds(packet):
    return packet.FCfield & 0x3


class Packet(object):
    """ Extract useful info from Scapy Packet"""
    def __init__(self, packet):
        #self.packet = packet
        print(packet.show())
        return
        self.time = packet.time
        self.ds = get_ds(packet)
        self.payload = packet.payload
        try:
            # print "PACKET", packet
            # print "PAYLOAD", packet.payload
            # self.size = len(packet.wepdata)
            self.size = len(packet.payload)
        except:
            print("exception!")
            self.size = 0

class Client(object):
    def __init__(self, packet, mac):
        self.mac = mac
        self.sent_packets = []
        self.received_packets = []
        self.packets = []
        self.add_packet(packet)

    def add_packet(self, packet):
        # print "add packet", self.mac, ds
        self.packets.append(packet)
        if packet.ds == SENT:
            self.sent_packets.append(packet)
        elif packet.ds == RECEIVED:
            self.received_packets.append(packet)
        else:
            client_mac = None
            print "client_mac None"

    def bandwidth(self):
        sent = sum(map(len, self.sent_packets))
        received = sum(map(len, self.received_packets))
        print "sent\t\t%d\nreceived\t%d" % (sent, received)

    def timing(self):
        t = None
        for p in self.packets:
            if t == None:
                print 0
                t = p.time
                continue
            print 1000*(p.time - t)
            t = p.time

    def buckets(self):
        start = self.packets[0].time
        end = self.packets[-1].time
        delta = math.ceil(end - start)
        num_buckets = int(math.ceil(delta / BUCKET_SIZE))
        self.sent_buckets = [0] * num_buckets
        self.received_buckets = [0] * num_buckets
        for packet in self.sent_packets:
            t = packet.time
            i = int((t - start) / BUCKET_SIZE)
            self.sent_buckets[i] += packet.size
        for packet in self.received_packets:
            t = packet.time
            i = int((t - start) / BUCKET_SIZE)
            print i, packet.size
            self.received_buckets[i] += packet.size
        # print self.sent_buckets
        # print self.received_buckets
        return BUCKET_SIZE, delta


    def __repr__(self):
        return self.mac + ' (%d,%d)' % (len(self.sent_packets), len(self.received_packets))


class Monitor(object):
    def __init__(self, pcap, mac_addr):
        self.pcap = pcap
        self.mac_addr = mac_addr
        #self.clients = {}
        self.client = None
        self.scan_pcap()

    def scan_pcap(self):
        print "scan_pcap START"
        cmd = "sudo tcpdump -nnvs0 -I -i en0 -G 5 -W 1 -w %s ether host %s" % (self.pcap, self.mac_addr)
        print "calling command", cmd
        subprocess.call(cmd, shell=True)
        print "command done, reading pcap"
        packets = rdpcap(self.pcap)
        # maybe ignore retry packets too?
        # data_packets = filter(lambda p:(p.type==2 and p.subtype==8), packets)
        #data_packets = []
        # count = 0
        print "scan_pcap READ"
        for p in packets:
            # count += 1
            try:
                if (p.type==2 and p.subtype==8):
                    #60:03:08:93:9c:54
                    # print p.addr2, p.addr1
                    if (p.addr2==self.mac_addr or p.addr1==self.mac_addr):
                        #data_packets.append(p)
                        packet = Packet(p)

                        if packet.ds == SENT:
                            client_mac = p.addr2
                        elif packet.ds == RECEIVED:
                            client_mac = p.addr1
                        else:
                            client_mac = None
                            # print "client_mac None"
                        # print ds, packet.addr1, packet.addr2, packet.addr3, packet.addr4
                        #if client_mac in self.clients:
                        if self.client == None:
                             print "!!!setting client"
                             self.client = Client(packet, client_mac)
                        else:
                            self.client.add_packet(packet)
            except:
                pass
        print "scan_pcap DONE"

                # p.show()
            # if (count % 100) == 0:
            #     print count

        #for raw_packet in data_packets:
        #print self.clients

# m = Monitor('80211.pcap', '94:10:3e:3c:e8:71')
# c = m.client
#
# total_bytes = 0
# for p in c.received_packets:
#     print p.time, len(p.payload)
#
#     total_bytes += len(p.payload)
#
# print total_bytes / (c.packets[-1].time - c.packets[0].time)

# c.buckets()
