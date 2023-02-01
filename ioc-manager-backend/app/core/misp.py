from pymisp import ExpandedPyMISP, MISPSighting
from pymisp import MISPEvent
from datetime import datetime
import requests


class misp_instance:
    def __init__(self, url, api_key) -> None:
        self.url = url
        self.api_key = api_key
        self.instance = ExpandedPyMISP("http://" + url, api_key, False)

    def parseTypes(self, type):
        if "ip" in type.lower():
            return "ip-src"
        return type.lower().replace("-", "")

    def setEvents(self, events, expiration="null"):
        self.events = {}
        aux = {event["info"]: event for event in self.instance.events()}
        self.updates = []
        ret = []
        if expiration != "null":
            tag = [
                a
                for a in self.instance.get_taxonomy("score")["entries"]
                if a["numerical_value"] == str(100)
            ][0]
        self.sightings = []

        for a in events.values:
            log = []
            if expiration != "null":
                for b in a[3]:
                    sight = MISPSighting()
                    sight.from_dict(
                        value=b,
                        source="Expiration from CTI Manager",
                        type=2,
                        timestamp=datetime.fromtimestamp(int(expiration[:10])),
                    )
                    self.sightings.append(sight)

            try:
                campaign = "IOC Manager"  # TODO: mirar si ficar sempre mateix event
                if campaign in self.events.keys():
                    [
                        self.events[campaign].add_attribute(
                            type=self.parseTypes(a[1]), value=b, comment=a[2]
                        )
                        for b in a[3]
                    ]
                else:
                    e = MISPEvent()
                    if campaign in aux.keys():
                        e.from_dict(Event=aux[campaign])
                        [
                            e.add_attribute(
                                type=self.parseTypes(a[1]),
                                value=b,
                                comment=a[2],
                                Tag=[tag["tag"]],
                            )
                            for b in a[3]
                        ]
                        self.updates.append(campaign)
                    else:
                        e.from_dict(
                            Event={
                                "info": campaign,
                                "published": False,
                                "Attribute": [
                                    {
                                        "type": self.parseTypes(a[1]),
                                        "value": b,
                                        "comment": a[2],
                                    }
                                    for b in a[3]
                                ],
                            }
                        )

                    self.events[campaign] = e
                log.extend(["Added to MISP"] * len(a[3]))
            except Exception as e:
                log.extend([e] * len(a[3]))
                continue
            ret.extend([log[0]] * len(a[3]))
        return ret

    def getLogs(self):
        iocs = self.instance.search("attributes", searchall="%Uploaded by:%")
        return [
            {
                "ioc": ioc["value"],
                "user": ioc["comment"].split("Uploaded by: ")[1],
            }
            for ioc in iocs["Attribute"]
        ]

    def push(self):
        for event in self.events.values():
            if event["info"] in self.updates:
                self.instance.update_event(event)
            else:
                self.instance.add_event(event)

        for sight in self.sightings:
            self.instance.add_sighting(sight)

    def deleteAttributes(self, df):
        values = [a[1] for a in df.values]
        delete = {}
        attributes = self.instance.search("attributes", value=values)["Attribute"]

        for a in attributes:
            if a["Event"]["id"] in delete:
                delete[a["Event"]["id"]].append(a["id"])
            else:
                delete[a["Event"]["id"]] = [a["id"]]
        headers = {
            "Authorization": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        for o in delete:
            requests.post(
                "http://" + self.url + "/attributes/deleteSelected/" + o,
                json={"Attribute": delete[o]},
                headers=headers,
            )

    def getIocs(self, types):
        return self.instance.search(
            controller="attributes",
            to_ids=True,
            type_attribute=types,
        )["Attribute"]
