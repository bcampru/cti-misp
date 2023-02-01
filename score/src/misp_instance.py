from pymisp import ExpandedPyMISP


class misp_instance:
    def __init__(self, url, api_key) -> None:
        self.instance = ExpandedPyMISP(url, api_key, False)
        self.taxonomy = self.instance.get_taxonomy("score")["entries"]

    def getScoreTaxonomy(self):
        return self.instance.build_complex_query(
            not_parameters=[a["tag"] for a in self.taxonomy]
        )

    def getThresholds(self):
        decaying_models = self.instance.decaying_models()
        result = {}
        for a in decaying_models:
            if a["DecayingModel"]["enabled"]:
                for b in a["DecayingModelMapping"]:
                    result[b["attribute_type"]] = int(
                        a["DecayingModel"]["parameters"]["threshold"]
                    )
        return result

    def getFilteredAttributes(self):
        return self.instance.search(
            controller="attributes",
            to_ids=0,
        )["Attribute"]

    def cleanIdsAttributes(self):
        attributes = self.instance.search(
            controller="attributes",
            tags=self.getScoreTaxonomy(),
            to_ids=True,
        )["Attribute"]
        result = []
        for a in attributes:
            a["to_ids"] = False
            a["timestamp"] = str(int(a["timestamp"]) + 1)
            result.append(a)
        self.push(result)

    def push(self, attributes):
        for attr in attributes:
            self.instance.update_attribute(attr)

    def updateScores(self):
        self.instance.search(
            controller="attributes",
            exclude_decayed=True,
        )

    def delete(self, attribute):
        self.instance.delete_attribute(attribute)
