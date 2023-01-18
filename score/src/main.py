import json
from pymisp import MISPAttribute
from misp_instance import misp_instance
import concurrent.futures
from virustotal import VirusTotalConnector
from abuseipdb import AbuseIPDB
from datetime import date
from dateutil.relativedelta import relativedelta
import os

key=os.getenv('MISP_API_KEY')
misp_host=os.getenv('MISP_HOST')
misp=misp_instance("http://localhost", "vANwHwHW4DI5k1BfbNe8oVsmUuJTlBDcg3K9mdT4")
#misp=misp_instance("http://"+misp_host, key)
date_3m = date.today() - relativedelta(months=+3)
attributes=misp.getFilteredAttributes(date_3m)
aipdb=AbuseIPDB()
vtconnector=VirusTotalConnector()

types={'ip':['ip-src', 'ip-dst'], 'vt':['sha256', 'md5', 'sha1', 'url', 'domain']}

class done:
    def __init__(self) -> None:
        self.attributes=[]
        self.cancel={}
        self.jobs={}

    def setJobs(self, jobs):
        self.jobs=jobs
        self.removeJobs()

    def removeJobs(self):
        for c in self.cancel.keys():
            if c in self.jobs.keys():
                for job in self.jobs[c]:
                        job.cancel()

    def done(self, attr, score, connector):
        if score==-1:
            self.cancel[connector]=1
            self.removeJobs()
            return

        tag=[a for a in misp.taxonomy if a['numerical_value']==str(score)][0]
        a=MISPAttribute()
        a.from_dict(Attribute=attr)
        a.add_tag(tag['tag'])
        self.attributes.append(a)
        print("Calculated score for IOC: "+attr["value"])

    def push(self):
        misp.push(self.attributes)
        return self.attributes

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ipexecutor, concurrent.futures.ThreadPoolExecutor(max_workers=10) as vtexecutor:
    try:
        done_instance=done()
        ip, vt=[],[]
        for a in attributes['Attribute']:
            if a['type'] in types['ip']:
                ip.append(a)
            elif a['type'] in types['vt']:
                vt.append(a)
        with open("ip.txt", "w") as ipf, open("vt.txt", "w") as vtf:
            ipf.write(json.dumps(ip))
            vtf.write(json.dumps(vt))

        resultsip = [ipexecutor.submit(aipdb._process_message, a, done_instance.done) for a in ip]
        resultsvt = [vtexecutor.submit(vtconnector._process_message, a, done_instance.done) for a in vt]
        #resultsvt=[]
        done_instance.setJobs({aipdb._SOURCE_NAME:resultsip, vtconnector._SOURCE_NAME:resultsvt})
        concurrent.futures.wait(resultsip+resultsvt)
        done=done_instance.push()
        with open("done.txt", "w") as donef:
            donef.write(json.dumps([[a["type"], a["value"]] for a in done]))
    except Exception as e:
        print(str(e))