data = [[1, 84, 1, 78], [19, 6923, 29, 21209], [52, 5262, 64, 66536], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [6, 960, 6, 1492], [4, 336, 12, 11458], [22, 2247, 51, 51276]]
results = ['idle', 'active', 'active', 'idle', 'idle', 'idle', 'idle', 'active', 'active',
 'active']

print len(data), len(results)


for i in range(len(data)):
    print "\t".join(map(str, data[i])) + "\t" + results[i]
