from pcap import Monitor

PREFIXES = {
    "94:10:3e": "BELKIN",
}

MAC_ADDR = '94:10:3e:3c:e8:71'
PCAP_FILE = 'temp.pcap'

m = Monitor(PCAP_FILE, PREFIXES, scan=True)
print m.make_training_data()
