import json
from tokenize import Number
from pymisp import MISPAttribute
from misp_instance import misp_instance
import concurrent.futures
from virustotal import VirusTotalConnector
from abuseipdb import AbuseIPDB
from datetime import date
from dateutil.relativedelta import relativedelta
import os

key = os.getenv("MISP_API_KEY")
misp_host = os.getenv("MISP_HOST")
misp = misp_instance("http://localhost", "vANwHwHW4DI5k1BfbNe8oVsmUuJTlBDcg3K9mdT4")
# misp=misp_instance("http://"+misp_host, key)
attributes = misp.getFilteredAttributes()
aipdb = AbuseIPDB()
vtconnector = VirusTotalConnector()
threshold = os.getenv("SCORE_THRESHOLD")

types = {"ip": ["ip-src", "ip-dst"], "vt": ["sha256", "md5", "sha1", "url", "domain"]}


class done:
    def __init__(self, misp_instance) -> None:
        self.attributes = []
        self.cancel = {}
        self.jobs = {}
        self.misp_instance = misp_instance

    def setJobs(self, jobs):
        self.jobs = jobs
        self.removeJobs()

    def removeJobs(self):
        for c in self.cancel.keys():
            if c in self.jobs.keys():
                for job in self.jobs[c]:
                    job.cancel()

    def done(self, attr, score, connector):
        if score == -1:
            self.cancel[connector] = 1
            self.removeJobs()
            return
        if score < int(threshold):
            self.misp_instance.delete(attr)
        else:
            tag = [a for a in misp.taxonomy if a["numerical_value"] == str(score)][0]
            a = MISPAttribute()
            a.from_dict(Attribute=attr)
            a.add_tag(tag["tag"])
            self.attributes.append(a)

    def push(self):
        misp.push(self.attributes)
        return self.attributes


with concurrent.futures.ThreadPoolExecutor(
    max_workers=20
) as ipexecutor, concurrent.futures.ThreadPoolExecutor(max_workers=10) as vtexecutor:
    try:
        done_instance = done(misp)
        ip, ipmanager, vt, vtmanager = [], [], [], []
        for a in attributes["Attribute"]:
            if a["type"] in types["ip"] and a["Event"]["info"] != "IOC Manager":
                ip.append(a)
            elif a["type"] in types["vt"] and a["Event"]["info"] != "IOC Manager":
                vt.append(a)
            elif a["type"] in types["ip"] and a["Event"]["info"] == "IOC Manager":
                ipmanager.append(a)
            elif a["type"] in types["vt"] and a["Event"]["info"] == "IOC Manager":
                vtmanager.append(a)
        ip = ipmanager + ip
        vt = vtmanager + vt
        with open("ip.txt", "w") as ipf, open("vt.txt", "w") as vtf:
            ipf.write(json.dumps(ip))
            vtf.write(json.dumps(vt))

        # aipdb._process_message(ip[0], done_instance.done)
        # vtconnector._process_message(vt[0], done_instance.done)
        resultsip = [
            ipexecutor.submit(aipdb._process_message, a, done_instance.done) for a in ip
        ]
        resultsvt = [
            vtexecutor.submit(vtconnector._process_message, a, done_instance.done)
            for a in vt
        ]
        # resultsvt=[]
        # resultsip=[]
        done_instance.setJobs(
            {aipdb._SOURCE_NAME: resultsip, vtconnector._SOURCE_NAME: resultsvt}
        )
        concurrent.futures.wait(resultsip + resultsvt)
        done = done_instance.push()
        with open("done.txt", "w") as donef:
            donef.write(json.dumps([[a["type"], a["value"]] for a in done]))
    except Exception as e:
        print(str(e))
