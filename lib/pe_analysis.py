import pefile
import hashlib
from datetime import datetime
from pprint import pprint
from lib import utils
from statistics import mean, stdev
from signify import signed_pe
from signify.exceptions import SignedPEParseError

# https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format

class PEFile:
    def __init__(self, filepath):
        self.filepath = filepath
        pe = pefile.PE(self.filepath)
        pe.full_load()
        self.pe = pe
        self.file_details = {}

    def analyze(self):
        try:
            file_details = {}
            file_details['imphash'] = self.pe.get_imphash()
            file_details['warnings'] = '; '.join(self.pe.get_warnings())
            file_details['compile_time'] = datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp)
            file_details['num_RVA_and_Sizes'] = self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            file_details['subsystem'] = pefile.SUBSYSTEM_TYPE[self.pe.OPTIONAL_HEADER.Subsystem]
            file_details['is_dll'] = self.pe.FILE_HEADER.IMAGE_FILE_DLL
            file_details['machine_type'] = pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine]
            file_details['entry_point'] = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            file_details['optional_header'] = self.pe.OPTIONAL_HEADER.ImageBase

            file_details.update(self.get_imports())
            file_details.update(self.get_exports())
            file_details.update(self.get_sections())
            file_details.update(self.get_resources())
            file_details.update(self.get_authenticode())
            self.file_details = file_details
            self.pe.close()
            return file_details
        except Exception as e:
            self.pe.close()
            return {'msg' : 'Error reading file: {} with exception: {}'.format(self.filepath, e)}


    def get_imports(self):
        file_details = {}
        file_details['imports'] = []
        file_details['import_summary'] = {'num_imports': 0, 'num_functions': 0, 'function_counts': [], 'imports': ''}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for import_entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                file_details['import_summary']['num_imports'] += 1
                dll_name = import_entry.dll.decode('utf-8')
                import_detail_entry = {'name': dll_name, 'functions': []}

                num_functions_per_import = 0
                for func in import_entry.imports:
                    num_functions_per_import += 1
                    file_details['import_summary']['num_functions'] += 1

                    func_name = func.name.decode('utf-8')
                    import_detail_entry['functions'].append({'address': func.address, 'function': func_name})
                file_details['import_summary']['function_counts'].append(num_functions_per_import)
                file_details['imports'].append(import_detail_entry)
            file_details['import_summary']['imports'] = '; '.join([entry['name'] for entry in file_details['imports']])

        return file_details

    def get_exports(self):
        file_details = {}
        file_details['exports'] = []
        file_details['export_summary'] = {'cnt': 0, 'exports' : ''}
        export_names = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                image_base = self.pe.OPTIONAL_HEADER.ImageBase
                file_details['export_summary']['cnt'] += 1
                export_name = entry.name.decode('utf-8')
                export_names.append(export_name)
                file_details['exports'].append(
                    {'name': export_name, 'base_address': image_base, 'address': (image_base + entry.address)})

        file_details['exports'] = '; '.join(export_names)

        return file_details

    def get_resources(self, depth=0, resource=None, file_details={}, resource_path=[]):
        if depth == 0:

            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    file_details.update(self.get_resources(depth + 1, resource, file_details, []))
                return {'resources' : file_details}
        else:
            if hasattr(resource, 'data'):
                resource_data = self.pe.get_data(resource.data.struct.OffsetToData, resource.data.struct.Size)
                md5 = hashlib.md5()
                md5.update(resource_data)
                md5_hash = md5.hexdigest()
                id = None
                name = None
                if resource.id:
                    id = str(resource.id)
                if resource.name:
                    name = str(resource.name)
                else:
                    name = str(pefile.RESOURCE_TYPE.get(resource.struct.Id))
                if id is not None:
                    resource_path.append(id)
                if name is not None:
                    resource_path.append(name)

                file_details[':'.join(resource_path)] = {'md5' : md5_hash,
                                                         'lang' : pefile.LANG.get(resource.data.lang, 'none'),
                                                         'sub_lang' : pefile.get_sublang_name_for_lang(resource.data.lang, resource.data.lang),
                                                         'type' : utils.get_type(buffer=resource_data).get('file_type', 'unknown'),
                                                         'size' : resource.data.struct.Size,
                                                         'offset' : resource.data.struct.OffsetToData}
                return file_details
            else:
                # We're at a directory and need to recurse deeper
                id = None
                name = None
                if resource.id:
                    id = resource.id
                if resource.name:
                    name = resource.name.string.decode('utf-8')
                else:
                    name = pefile.RESOURCE_TYPE.get(resource.struct.Id)
                if id is not None:
                    resource_path.append(str(id))
                if name is not None:
                    resource_path.append(str(name))

                for child_resource in resource.directory.entries:
                    file_details.update(self.get_resources(depth+1, child_resource, file_details, resource_path))

                return file_details

        return file_details

    def get_sections(self):
        file_details = {}
        file_details['sections'] = {}
        try:
            for section in self.pe.sections:
                section_name = section.Name.decode('utf-8').replace('\x00', '')
                file_details['sections'][section_name] = {'virtual_address': section.VirtualAddress,
                                                          'virtual_size': section.Misc_VirtualSize,
                                                          'raw_size': section.SizeOfRawData,
                                                          'entropy': section.get_entropy(),
                                                          'md5': section.get_hash_md5(),
                                                          'sha1': section.get_hash_sha1(),
                                                          'sha256': section.get_hash_sha256(),
                                                          'characteristics' : hex(section.Characteristics)
                                                          }
        except:
            return file_details

        return file_details

    def get_authenticode(self):
        file_details = {'authenticode_msg' : 'Unable to verify authenticode', 'authenticode_issuer_dn' : '', 'authenticode' : {}}
        with open(self.filepath, "rb") as f:
            pefile = signed_pe.SignedPEFile(f)
            try:
                pefile.verify()
                file_details['authenticode_msg'] = 'Signed'

                file_details['authenticode']['signature_data'] = []
                for signed_data in pefile.signed_datas:
                    for cert in signed_data.certificates:
                        entry = {}
                        entry['issuer'] = cert.issuer.prettyPrint()
                        entry['issuer_dn'] = cert.issuer_dn
                        entry['serial_no'] = cert.serial_number
                        entry['signature_algorithm'] = cert.signature_algorithm.prettyPrint()
                        entry['subject_dn'] = cert.subject_dn
                        entry['valid_to'] = cert.valid_to.isoformat()
                        entry['valid_from'] = cert.valid_from.isoformat()
                        file_details['authenticode']['signature_data'].append(entry)
                file_details['authenticode_subject_dn'] = '\n'.join([entry['subject_dn'] for entry in file_details['authenticode']['signature_data']])
            except SignedPEParseError:
                file_details['authenticode_msg'] = 'The PE file does not contain a certificate table.'
            except Exception as e:
                file_details['authenticode_msg'] = str(e)

        return file_details


    def summarize_results(self):

        fields = ['imphash', 'warnings', 'num_RVA_and_Sizes', 'subsystem', 'is_dll', 'machine_type', 'entry_point',
                  'optional_header', 'msg']

        summary = {}

        for field in fields:
            summary[field] = self.file_details.get(field, '')

        try:
            summary['compile_time'] = ''
            summary['compile_time'] = self.file_details['compile_time'].isoformat()
            summary['days_since_compiled'] = (datetime.now() - self.file_details['compile_time']).days
        except:
            summary['days_since_compiled'] = ''

        # summarize imports
        imports = self.file_details.get('import_summary', {})
        all_imports = self.file_details.get('imports', [])
        for import_entry in all_imports:
            library = import_entry.get('name', '')
            functions = import_entry.get('functions', [])
            for function_entry in functions:
                function_name = function_entry.get('function', '')

        summary['imports_cnt'] = imports.get('num_imports', 0)
        summary['imports_num_functions'] = imports.get('num_functions', 0)
        summary['imports_avg_functions'] = mean(imports.get('function_counts', [0]))
        summary['imports_stdev_functions'] = stdev(imports.get('function_counts', [0, 0]))
        summary['imports'] = imports.get('imports', '')

        # summarize exports
        exports = self.file_details.get('export_summary', {})
        summary['exports_cnt'] = exports.get('cnt', 0)
        summary['exports'] = exports.get('exports', '')

        # sections
        sections = self.file_details.get('sections', {})
        summary['sections'] = '; '.join(list(sections.keys()))
        summary['sections_cnt'] = len(sections)
        virtual_raw_differences = [abs(section['virtual_size'] - section['raw_size']) for section_name, section in sections.items()]
        summary['sections_min_raw_virtual_diff'], summary['sections_max_raw_virtual_diff'], summary['sections_avg_raw_virtual_diff'], summary['sections_stdev_raw_virtual_diff'] = utils.basic_stats(virtual_raw_differences)

        section_entropy = [section['entropy'] for section_name, section in sections.items()]
        summary['sections_min_entropy'], summary['sections_max_entropy'], summary['sections_avg_entropy'], summary['sections_stdev_entropy'] = utils.basic_stats(section_entropy)

        # resources
        resources = self.file_details.get('resources', {})
        summary['resources_cnt'] = len(resources)
        summary['resources_languages'] = '; '.join(set([value.get('lang', '') for key, value in resources.items()]))
        summary['resources_types'] = '; '.join(set([value.get('type', '') for key, value in resources.items()]))
        resources_sizes = [value.get('size', 0) for key, value in resources.items()]
        summary['resources_min_size'], summary['resources_max_size'], summary['resources_avg_size'], summary['resources_stdev_size'] = utils.basic_stats(resources_sizes)

        # Authenticode
        summary['authenticode'] = self.file_details.get('authenticode_msg', '')
        summary['authenticode_issuer_dn'] = self.file_details.get('authenticode_issuer_dn', '')

        return summary



if __name__ == "__main__":
    executable = PEFile(r'E:\packed_exes\unpacked_exe\bitsadmin.exe')
    executable.analyze()
    pprint(executable.summarize_results())
    pprint(executable.analyze())
