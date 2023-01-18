# -*- coding: utf-8 -*-
"""VirusTotal enrichment module."""

from .builder import VirusTotalBuilder
from .client import VirusTotalClient
import os

class VirusTotalConnector:
    """VirusTotal connector."""

    _SOURCE_NAME = "VirusTotal"
    _API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        token = os.getenv('VIRUSTOTAL_API_KEY')
        self.client = VirusTotalClient(self._API_URL, token)
        # Cache to store YARA rulesets.
        self.yara_cache = {}
        
    def _retrieve_yara_ruleset(self, ruleset_id: str) -> dict:
        """
        Retrieve yara ruleset.

        If the yara is not in the cache, make an API call.

        Returns
        -------
        dict
            YARA ruleset object.
        """
        if ruleset_id in self.yara_cache:
            ruleset = self.yara_cache[ruleset_id]
        else:
            ruleset = self.client.get_yara_ruleset(ruleset_id)
            self.yara_cache[ruleset_id] = ruleset
        return ruleset

    def _process_file(self, observable):
        json_data = self.client.get_file_info(observable["value"])
        assert json_data
        if "error" in json_data:
            print(json_data["error"]["message"])
            if json_data["error"]["code"]=='NotFoundError':
                return 0
            if json_data["error"]["code"]=="QuotaExceededError":
                return -1
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            json_data["data"]
        )

        # Add YARA rules (only if a rule is given).
        #for yara in json_data["data"]["attributes"].get(
        #    "crowdsourced_yara_results", []
        #):
        #    ruleset = self._retrieve_yara_ruleset(
        #        yara.get("ruleset_id", "No ruleset id provided")
        #    )
        #    builder.create_yara(
        #        yara,
        #        ruleset,
        #        json_data["data"]["attributes"].get("creation_date", None),
        #    )

        # dades VT note = "VirusTotal Report", f"```\n{json.dumps(json_data, indent=2)}\n```"
        print("va")
        return builder.score

    def _process_ip(self, observable):
        json_data = self.client.get_ip_info(observable["value"])
        assert json_data
        if "error" in json_data:
            if json_data["error"]["code"]=='NotFoundError':
                return 0
            if json_data["error"]["code"]=="QuotaExceededError":
                return -1
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            json_data["data"]
        )

        #es podria extreure info de asn i de localització si es volgues. Està guardat a json_data

        #notes=builder.create_notes() #Dades de VT, per si es vol utilitzar
        return builder.score

    def _process_domain(self, observable):
        json_data = self.client.get_domain_info(observable["value"])
        assert json_data
        if "error" in json_data:
            if json_data["error"]["code"]=='NotFoundError':
                return 0
            if json_data["error"]["code"]=="QuotaExceededError":
                return -1
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            json_data["data"]
        )

        # Create IPv4 address observables for each A record
        # and a Relationship between them and the observable.
        #for ip in [
        #    r["value"]
        #    for r in json_data["data"]["attributes"]["last_dns_records"]
        #    if r["type"] == "A"
        #]:
        #    
        #    ip es totes les ips que direccionen a url
        
        #notes=builder.create_notes() #Dades de VT, per si es vol utilitzar

        return builder.score

    def _process_url(self, observable):
        json_data = self.client.get_url_info(observable["value"])
        assert json_data
        if "error" in json_data:
            if json_data["error"]["code"]=='NotFoundError':
                return 0
            if json_data["error"]["code"]=="QuotaExceededError":
                return -1
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = VirusTotalBuilder(
            json_data["data"]
        )
        #notes=builder.create_notes() #Dades de VT, per si es vol utilitzar
        return builder.score

    def _process_message(self, observable, callback):
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, "
                "check the group of the connector user)"
            )

        match observable["type"]:
            case 'sha256' | 'md5' | 'sha1':
                score = self._process_file(observable)
            case 'ip-src' | 'ip-dst':
                score = self._process_ip(observable)
            case "domain":
                score = self._process_domain(observable)
            case "url":
                score = self._process_url(observable)
            case _:
                return "incorrect_type"
        callback(observable, score, self._SOURCE_NAME)
