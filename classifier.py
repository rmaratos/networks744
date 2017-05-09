import sys
from sklearn import svm

from data import active1, active2, active3
from data import longidle1, longidle2, longidle3, longidle4, longidle4, longidle5
from sklearn import preprocessing
IDLE = 'idle'
ACTIVE = 'active'

DATA SETUP

idle_training =  longidle1.DATA[0][1] + longidle2.DATA[0][1] + longidle4.DATA[0][1] + longidle5.DATA[0][1] + longidle3.DATA[0][1]
active_training = active1.DATA[0][1] + active2.DATA[0][1] + active3.DATA[0][1]

active_training = active_training

# END DATA SETUP

print "idle training len=" + str(len(idle_training))
print "active training len=" + str(len(active_training))


X = idle_training + active_training
Y = [IDLE]*len(idle_training) + \
    [ACTIVE]*len(active_training)

for i in range(len(X)):
    print X[i], Y[i]

clf = svm.SVC()
clf.fit(X,Y)


from data import phoneidle1, phoneidle2, phoneidle3
from data import music1, music2, music3
from data import weather1, weather2, weather3

ALEXA_IDLE = 'alexa_idle'
ALEXA_WEATHER = 'alexa_weather'
ALEXA_MUSIC = 'alexa_music'

alexa_idle_training = phoneidle1.DATA[0][1] + phoneidle2.DATA[0][1] + phoneidle3.DATA[0][1]
alexa_music_training = music1.DATA[0][1] + music2.DATA[0][1] + music3.DATA[0][1]
alexa_weather_training = weather1.DATA[0][1] + weather2.DATA[0][1] + weather3.DATA[0][1]

print "alexa idle training len=" + str(len(alexa_idle_training))
print "alexa music training len=" + str(len(alexa_music_training))
print "alexa weather training len=" + str(len(alexa_weather_training))

Alexa_X = alexa_idle_training + alexa_music_training + alexa_weather_training
Alexa_Y = [ALEXA_IDLE]*len(alexa_idle_training) + \
    [ALEXA_WEATHER]*len(alexa_weather_training) + \
    [ALEXA_MUSIC]*len(alexa_music_training)

Alexa_X = preprocessing.scale(Alexa_X)
alexa_clf = svm.SVC()
alexa_clf.fit(Alexa_X, Alexa_Y)

from pcap import Monitor

CLASSIFIERS = {
    # "94:10:3e": clf,
    "2c:33:61": alexa_clf
}
PREFIXES = {
    "94:10:3e:3c:E8:71": "BELKIN",
    # "b4:5d:50": "Macbook",
    "2c:33:61:90:98:f5": "iPhone"
}


MAC_ADDR = '94:10:3e:3c:e8:71'
PCAP_FILE = 'temp.pcap'

from collections import Counter

def prediction(results):
    counts = Counter(results)
    total = sum(counts.values())
    s = ""
    for label, count in counts.most_common():
        s += label + "(" + str(round(100.0*count/total, 2)) + "%) "
    return s

read = False
print len(sys.argv)
if len(sys.argv) > 1:
    PCAP_FILE = sys.argv[1]
    read = True
    print ""
    print PCAP_FILE

m = Monitor(PCAP_FILE, PREFIXES, read=read)
for i in range(100):
    if read:
        m.read_pcap()
    else:
        m.scan_pcap()
    print "Current Clients:", len(m.clients)
    for device, data in m.make_training_data():
        print "New testing data for ", device
        print data
        prefix = device[7:15]
        classifier = CLASSIFIERS[prefix]
        results = classifier.predict(data)
        print "Results:", results
        print "PREDICTION: " + prediction(results)
        print
    if read:
        break
