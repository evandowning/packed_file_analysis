import yara
from pprint import pprint

class Yara_Engine:
    def __init__(self, rules_path=None, compiled_rules_path=None):
        try:
            rules = yara.load(compiled_rules_path)
        except:
            rules = yara.compile(filepath=rules_path)
            if compiled_rules_path is not None:
                rules.save(compiled_rules_path)
        self.rules = rules
        self.file_details = {}

    def analyze(self, file_path):
        yara_results = self.rules.match(file_path, timeout=60)
        hits = {'hits' : []}
        rule_names = []
        for result in yara_results:
            entry = result.meta
            rule_name = result.rule
            rule_names.append(rule_name)
            namespace = result.namespace
            description = entry.get('description', '')
            hits['hits'].append({'rule_name' : rule_name, 'namespace' : namespace, 'description' : description})
        hits['rule_names'] = ';'.join(rule_names)

        self.file_details = hits

        return hits

    def summarize_results(self):
        self.file_details

if __name__ == "__main__":
    yara_engine = Yara_Engine('/home/analyst/rules/Packers/peid.yar')
    pprint(yara_engine.analyze('/home/analyst/packed_exes/unpacked_exe/bitsadmin.exe'))
