
def test(testing_data, label):
    if not testing_data:
        return
    correct = incorrect = 0

    for packet in testing_data:
        result = clf.predict([packet])
        if result[0] == label:
            correct += 1
        else:
            incorrect += 1

    print label
    print str(correct) + "/" + str(correct + incorrect)
