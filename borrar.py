import json
with open("./done.txt.old", "r") as done:
    parsed=json.load(done)
    types={}
    ip=[a for a in parsed if "ip" in a[0]]
    vt=[a for a in parsed if "ip" not in a[0]]
    for a in parsed:
        if a[0] in types.keys():
            types[a[0]]+=1
        else:
            types[a[0]]=0
    print("final")