from pymisp import ExpandedPyMISP

class misp_instance:
    def __init__(self, url, api_key) -> None:
        self.instance = ExpandedPyMISP(url, api_key, False)
        self.taxonomy=self.instance.get_taxonomy("score")['entries']

    def getScoreTaxonomy(self):
        return self.instance.build_complex_query(not_parameters=[a['tag'] for a in self.taxonomy])

    def getFilteredAttributes(self, date):
        a=self.instance.search(include_sightings=False, include_correlations=False, include_decay_score=False, controller='attributes', tags=self.getScoreTaxonomy(), timestamp='100d')
        a['Attribute']=a['Attribute']+self.instance.search(include_sightings=False, include_correlations=False, include_decay_score=False, controller='attributes', timestamp=['10000d', '100d'])['Attribute']
        self.updates=[b['uuid'] for b in a['Attribute']]
        return a

    def push(self, attributes):
        for attr in attributes:
            if attr['uuid'] in self.updates:
                self.instance.update_attribute(attr)
            else:
                self.instance.add_attribute(attr)
