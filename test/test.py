#!/usr/bin/python3

import sys
import json
import subprocess

from subprocess import Popen, PIPE

#outFile = open('result.txt', 'wb')
#outFile.write(out)
#outFile.close()

SERVER_LOC = { "host" : "localhost", "port" : "6897" }

def startSubscriber(topic):
    return subprocess.Popen(["../build/memos", SERVER_LOC["host"], SERVER_LOC["port"], topic],
            stdout=subprocess.PIPE)

def publish(topic, message):
    subprocess.Popen(["../build/memop", SERVER_LOC["host"], SERVER_LOC["port"], topic, message],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

def runTest(inputCfg):
    print("Running {}".format(inputCfg["name"]))

    # Start server
    server = subprocess.Popen(["../build/memod", SERVER_LOC["port"]],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    # Setup subscribers
    subRes1 = startSubscriber("TEST")
    subRes2 = startSubscriber("TEST")
    subRes3 = startSubscriber("TEST2")

    # Publish some messages
    publish("TEST", "hohoho")
    publish("TEST", "quit")
    publish("TEST2", "quit")

    # Check results
    for line in iter(subRes1.stdout.readline, b''):
        print("S1>>> " + str(line).rstrip())

    for line in iter(subRes2.stdout.readline, b''):
        print("S2>>> " + str(line).rstrip())

    for line in iter(subRes3.stdout.readline, b''):
        print("S3>>> " + str(line).rstrip())

    # Tidy up
    server.kill()

allTests = json.loads(open(sys.argv[1]).read())
for test in allTests:
    runTest(test)
