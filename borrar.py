import json
with open("./done.txt", "r") as done, open("./ip.txt", "r") as ipf, open("./vt.txt", "r") as vtf:
    parsed=json.load(done)
    ips=json.load(ipf)
    ips=[a['value'] for a in ips]
    vtf=json.load(vtf)
    
    hash=[a['value'] for a in vtf if a["type"] in ["md5", "sha256", "sha1"]]
    dominios=[a['value'] for a in vtf if a["type"] in ["url"]]
    urls=[a['value'] for a in vtf if a["type"] in ["domain"]]

    types={}
    ip=[a for a in parsed if "ip" in a[0]]
    ips=[a[1] for a in ip if a[1] not in ips]
    vt=[a for a in parsed if "ip" not in a[0]]
    for a in parsed:
        if a[0] in types.keys():
            types[a[0]]+=1
        else:
            types[a[0]]=0
    print("final")