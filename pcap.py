from scapy.all import rdpcap
import logging, math, subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from Tkinter import *
import traceback

SENT = 1
RECEIVED = 2
BUCKET_SIZE = 5
def get_ds(packet):
    return packet.FCfield & 0x3


class Packet(object):
    """ Extract useful info from Scapy Packet"""
    def __init__(self, packet, mac_addr):
        #self.packet = packet
        # print(packet.show())
        self.time = packet.time
        self.ds = get_ds(packet)
        self.mac_addr = mac_addr
        self.sport = packet.sport
        self.dport = packet.dport
        # self.payload = packet.payload
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
        self.sent_count_buckets = [0] * num_buckets
        self.received_count_buckets = [0] * num_buckets
        for packet in self.sent_packets:
            t = packet.time
            i = int((t - start) / BUCKET_SIZE)
            self.sent_buckets[i] += packet.size
            self.sent_count_buckets[i] += 1
        for packet in self.received_packets:
            t = packet.time
            i = int((t - start) / BUCKET_SIZE)
            # print i, packet.size
            self.received_buckets[i] += packet.size
            self.received_count_buckets[i] += 1

        # print self.sent_buckets
        # print self.received_buckets

        for packet in self.sent_packets:
            t = packet.time
            i = int((t - start) / BUCKET_SIZE)
            packet.bucket_size = self.sent_buckets[i]
            packet.bucket_count = self.sent_count_buckets[i]
        for packet in self.received_packets:
            t = packet.time
            i = int((t - start) / BUCKET_SIZE)
            # print i, packet.size
            packet.bucket_size = self.received_buckets[i]
            packet.bucket_count = self.received_count_buckets[i]

        # print self.sent_buckets
        # print self.received_buckets
        return BUCKET_SIZE, delta


    def __repr__(self):
        return self.mac + ' (%d,%d)' % (len(self.sent_packets), len(self.received_packets))


class Monitor(object):
    def __init__(self, pcap, mac_addr, scan=False):
        self.pcap = pcap
        self.mac_addr = mac_addr
        #self.clients = {}
        self.client = None
        if scan:
            self.scan_pcap()
        else:
            self.read_pcap()

    def scan_pcap(self):
        print "scan_pcap START"
        cmd = "sudo tcpdump -nnvs0 -I -i en0 -G 5 -W 1 -w %s ether host %s" % (self.pcap, self.mac_addr)
        print "calling command", cmd
        subprocess.call(cmd, shell=True)
        print "command done, reading pcap"
        self.read_pcap()

    def read_pcap(self):
        packets = rdpcap(self.pcap)
        print "scan_pcap READ"
        i = 0
        for p in packets:
            i += 1
            try:
                if (p.type==2 and p.subtype==8):
                    # print p.addr2, p.addr1, self.mac_addr
                    if (p.addr2==self.mac_addr or p.addr1==self.mac_addr):
                        packet = Packet(p, self.mac_addr)
                        # if i == 2:
                        # print p.show()
                        # print "SIZE", len(p.getlayer('TCP').payload)
                        # break

                        # print packet.ds, packet.addr1, packet.addr2, packet.addr3, packet.addr4
                        if packet.ds == SENT:
                            client_mac = p.addr2
                        elif packet.ds == RECEIVED:
                            client_mac = p.addr1
                        else:
                            client_mac = None
                        if self.client == None:
                             print "!!!setting client"
                             self.client = Client(packet, client_mac)
                        else:
                            self.client.add_packet(packet)
            except:
                print "error!!!"
                # print p.show()
                # traceback.print_exc()
                pass
        print "scan_pcap DONE"

                # p.show()
            # if (count % 100) == 0:
            #     print count

        #for raw_packet in data_packets:
        #print self.clients

def make_training_data(pcap, mac):
    m = Monitor(pcap,mac)
    c = m.client

    print len(c.packets)
    print len(c.sent_packets)
    print len(c.received_packets)

    print c.buckets()

    # PACKET DATA
    # packet.time = timestamp
    # packet.ds = SENT/RECEIVED
    # packet.size = size of payload

    training_data = []
    for p in c.packets:
        split_addr = p.mac_addr.split(':')
        mac_addr0 = int(split_addr[0], 16)
        mac_addr1 = int(split_addr[1], 16)
        mac_addr2 = int(split_addr[2], 16)
        training_data.append([int(p.ds), p.size, mac_addr0, mac_addr1, mac_addr2,
                              p.sport, p.dport, p.bucket_size, p.bucket_count])


    # for packet in training_data:
    #     print packet
    return str(training_data)
# print len(training_data)

with open('data/active.py', 'w') as f:
    s = make_training_data('active.pcap', '94:10:3e:3c:e8:71')
    f.write('DATA=' + s)

with open('data/startup.py', 'w') as f:
    s = make_training_data('startup2.pcap', '94:10:3e:3c:e8:71')
    f.write('DATA=' + s)
