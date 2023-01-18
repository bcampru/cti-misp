# -*- coding: utf-8 -*-
"""VirusTotal builder module."""
import datetime
import json
from typing import Optional

import plyara
import plyara.utils

class VirusTotalBuilder:
    """VirusTotal builder."""

    def __init__(
        self,
        data: dict,
    ) -> None:
        """Initialize Virustotal builder."""
        self.attributes = data["attributes"]
        self.score = VirusTotalBuilder._compute_score(
            self.attributes["last_analysis_stats"]
        )

        # Add the external reference.
        self.link = self._extract_link(data["links"]["self"]) #link de VT equivalent a IOC

    @staticmethod
    def _compute_score(stats: dict) -> int:
        """
        Compute the score for the observable.

        score = malicious_count / total_count * 100

        Parameters
        ----------
        stats : dict
            Dictionary with counts of each category (e.g. `harmless`, `malicious`, ...)

        Returns
        -------
        int
            Score, in percent, rounded.
        """
        return round(
            (
                stats["malicious"]
                / (stats["harmless"] + stats["undetected"] + stats["malicious"])
            )
            * 100
        )

    def create_notes(self):
        """
        Create Notes with the analysis results and categories.

        Notes are directly append in the bundle.
        """
        ret={}
        if self.attributes["last_analysis_stats"]["malicious"] != 0:
            ret["VirusTotal Positives"]=f"""```\n{
                json.dumps(
                    [v for v in self.attributes["last_analysis_results"].values()
                     if v["category"] == "malicious"], indent=2
                )}\n```"""

        if "categories" in self.attributes:
            ret["VirusTotal Positives"]=f'```\n{json.dumps(self.attributes["categories"], indent=2)}\n```'
        return ret

    def create_yara(
        self, yara: dict, ruleset: dict, valid_from: Optional[float] = None
    ):
        """
        Create an indicator containing the YARA rule from VirusTotal and link it to the observable.

        Parameters
        ----------
        yara : dict
            Yara ruleset to use for the indicator.
        ruleset : dict
            Yara ruleset to use for the indicator.
        valid_from : float, optional
            Timestamp for the start of the validity.
        """
        valid_from_date = (
            datetime.datetime.min
            if valid_from is None
            else datetime.datetime.utcfromtimestamp(valid_from)
        )
        ruleset_id = yara.get("id", "No ruleset id provided")

        # Parse the rules to find the correct one.
        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset["data"]["attributes"]["rules"])
        rule_name = yara.get("rule_name", "No ruleset name provided")
        rule = [r for r in rules if r["rule_name"] == rule_name]
        if len(rule) == 0:
            return

        #indicator = stix2.Indicator(
        #    created_by_ref=self.author,
        #    name=yara.get("rule_name", "No rulename provided"),
        #    description=f"""```\n{json.dumps(
        #        {
        #            "description": yara.get("description", "No description provided"),
        #            "author": yara.get("author", "No author provided"),
        #            "source": yara.get("source", "No source provided"),
        #            "ruleset_id": ruleset_id,
        #            "ruleset_name": yara.get(
        #                "ruleset_name", "No ruleset name provided"
        #            ),
        #        }, indent=2
        #    )}\n```""",
        #    confidence=self.helper.connect_confidence_level,
        #    pattern=plyara.utils.rebuild_yara_rule(rule[0]),
        #    pattern_type="yara",
        #    valid_from=self.helper.api.stix2.format_date(valid_from_date),
        #    custom_properties={
        #        "x_opencti_main_observable_type": "StixFile",
        #        "x_opencti_score": self.score,
        #    },
        #)

    @staticmethod
    def _extract_link(link: str) -> Optional[str]:
        """
        Extract the links for the external reference.

        For the gui link, observable type need to be singular.

        Parameters
        ----------
        link : str
            Original link used for the query

        Returns
        -------
            str, optional
                Link to the gui of the observable on VirusTotal website, if any.
        """
        for k, v in {
            "files": "file",
            "ip_addresses": "ip-address",
            "domains": "domain",
            "urls": "url",
        }.items():
            if k in link:
                return link.replace("api/v3", "gui").replace(k, v)
        return None