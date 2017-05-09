from scapy.all import rdpcap
import logging, math, subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from Tkinter import *
import traceback

SENT = 1
RECEIVED = 2
BUCKET_SIZE = 3
RECORD_LENGTH = 3
PREFIX_LENGTH = 17
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
        # self.sport = packet.sport
        # self.dport = packet.dport
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
    def __init__(self, packet, mac, device_type, recording_start, recording_end):
        self.name = device_type + "(" + mac + ")"
        print "New Client: " + self.name
        self.mac = mac
        self.sent_packets = []
        self.received_packets = []
        self.packets = []
        self.add_packet(packet)
        self.device_type = device_type
        self.recording_start = recording_start
        self.recording_end = recording_end

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
        start = self.recording_start
        end = self.recording_end
        # print "PACKETS", len(self.packets), start, end
        delta = math.ceil(end - start)
        num_buckets = int(math.ceil(delta / BUCKET_SIZE))
        # print "NUMBUCKETS=", num_buckets, delta, BUCKET_SIZE
        self.sent_buckets = [0] * num_buckets
        self.received_buckets = [0] * num_buckets
        self.sent_count_buckets = [0] * num_buckets
        self.received_count_buckets = [0] * num_buckets
        for packet in self.sent_packets:
            t = packet.time
            i = int((t - start) / BUCKET_SIZE)
            # print "i=", i, BUCKET_SIZE, len(self.sent_buckets), t
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

    def clear(self, start, end):
        self.sent_packets = []
        self.received_packets = []
        self.packets = []
        self.recording_start = start
        self.recording_end = end

    def __repr__(self):
        return self.mac + ' (%d,%d)' % (len(self.sent_packets), len(self.received_packets))


class Monitor(object):
    def __init__(self, pcap, prefixes, read=False):
        self.pcap = pcap
        self.prefixes = prefixes
        print prefixes
        # self.mac_addr = mac_addr
        self.clients = {}
        # self.clients = None
        if read:
            self.read_pcap()

    def scan_pcap(self):
        # print "scan_pcap START"
        cmd = "sudo tcpdump -nnvs0 -I -i en0 -G %d -W 1 -w %s &> /dev/null" % (RECORD_LENGTH, self.pcap)
        # print "calling command", cmd
        subprocess.call(cmd, shell=True)
        # print "command done, reading pcap"
        self.read_pcap()

    def read_pcap(self):
        packets = rdpcap(self.pcap)

        start = packets[0].time
        end = packets[-1].time

        device_set = set()

        for clients in self.clients.values():
            clients.clear(start, end)
        # print "scan_pcap READ"
        i = 0
        errors = 0
        for p in packets:
            i += 1
            try:
                # print(p.type, p.subtype)
                # break
                # print p.addr1, p.addr2, p.addr3, get_ds(p)
                if (p.type==2 and p.subtype==8):
                    device_set.add(p.addr1)
                    device_set.add(p.addr2)
                    if p.addr1 in self.clients:
                        # print "Addr1 already in clients"
                        packet = Packet(p, p.addr1)
                        packet.ds = RECEIVED
                        self.clients[p.addr1].add_packet(packet)
                    elif p.addr2 in self.clients:
                        # print "Addr2 already in clients"
                        packet = Packet(p, p.addr2)
                        packet.ds = SENT
                        self.clients[p.addr2].add_packet(packet)
                    elif p.addr3 in self.clients:
                        packet = Packet(p, p.addr3)
                        self.clients[p.addr3].add_packet(packet)
                    else:
                        # print p.addr2, p.addr1, self.mac_addr
                        prefix_1 = p.addr1[:PREFIX_LENGTH]
                        prefix_2 = p.addr2[:PREFIX_LENGTH]
                        prefix_3 = p.addr3[:PREFIX_LENGTH]
                        # print prefix_1, prefix_2, prefix_3

                        if (prefix_1 in self.prefixes):
                            # print "prefix 1 in prefixes"
                            packet = Packet(p, p.addr1)
                            packet.ds = RECEIVED
                            self.clients[p.addr1] = Client(packet, p.addr1, self.prefixes[prefix_1], start, end)
                        elif (prefix_2 in self.prefixes):
                            # print "prefix 2 in prefixes"
                            packet = Packet(p, p.addr2)
                            packet.ds = SENT
                            self.clients[p.addr2] = Client(packet, p.addr2, self.prefixes[prefix_2], start, end)
                        elif (prefix_3 in self.prefixes):
                            # print "prefix 3 in prefixes"
                            packet = Packet(p, p.addr3)
                            self.clients[p.addr3] = Client(packet, p.addr3, self.prefixes[prefix_3], start, end)
            except:
                # print "error!!!"
                # print p.show()
                # errors += 1
                # traceback.print_exc()
                # if errors == 10:
                #     break
                # break
                pass

        # for device in sorted(device_set):
        #     print device
        print_devices(device_set)

    def make_training_data(self):
        training_data_list = []
        for c in self.clients.values():

            c.buckets()
            training_data = []

            for i in range(len(c.received_buckets)):
                training_data.append([c.received_count_buckets[i], c.received_buckets[i], c.sent_count_buckets[i], c.sent_buckets[i]])

            training_data_list.append((c.name, training_data))

        return training_data_list

import requests
def print_devices(macs):
    d = {}
    for mac in macs:
        response = requests.get("http://macvendors.co/api/" + mac).json()
        result = response.get("result")
        if result is None:
            continue
        company = result.get("company")
        if company:
            print mac + "-> " + company
        if company in d:
            d[company] += 1
        else:
            d[company] = 1
    for company in d:
        print company, d[company]

# with open('data/active.py', 'w') as f:
#     s = make_training_data('active.pcap', '94:10:3e:3c:e8:71')
#     f.write('DATA=' + s)
#
# with open('data/startup.py', 'w') as f:
#     s = make_training_data('startup.pcap', '94:10:3e:3c:e8:71')
#     f.write('DATA=' + s)
PREFIXES = {
    "94:10:3e:3c:E8:71": "BELKIN",
    # "b4:5d:50": "Macbook",
    "2c:33:61:90:98:f5": "iPhone"
}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print "usage pcap.py pcap_file output_file"
    else:
        m = Monitor(sys.argv[1], PREFIXES, read=True)
        with open(sys.argv[2], 'w') as f:
            s = m.make_training_data()
            f.write('DATA=' + str(s))
