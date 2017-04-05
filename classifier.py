from sklearn import svm

from data import active
from data import startup

print len(active.DATA)
print len(startup.DATA)

middle = len(active.DATA)/2
training_active = active.DATA[:middle]
testing_active = active.DATA[middle:]

middle = len(startup.DATA)/2
training_startup = startup.DATA[:middle]
testing_startup = startup.DATA[middle:]

X = training_active + training_startup
Y = ['active']*len(training_active) + ['startup']*len(training_startup)

# print len(X)
# print
# print len(Y)

clf = svm.SVC()
clf.fit(X,Y)


# subset = X[len(active.DATA) - 10: len(active.DATA) + 10]

correct = 0
incorrect = 0
for packet in testing_active:
    result =  clf.predict([packet])
    if result[0] == 'active':
        correct += 1
    else:
        incorrect += 1

print correct, incorrect

correct = 0
incorrect = 0


for packet in testing_startup:
    result = clf.predict([packet])
    if result[0] == 'startup':
        correct += 1
    else:
        incorrect += 1

print correct, incorrect
