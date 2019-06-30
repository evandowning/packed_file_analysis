from exiftool import ExifTool
from pprint import pprint

# http://smarnach.github.io/pyexiftool/#
# sudo apt install libimage-exiftool-perl

class Exif_Engine:
    def __init__(self):
        self.file_details = {}

    def analyze(self, file_path):
        with ExifTool() as et:
            metadata = et.get_metadata(file_path)

        result = {key:value for key, value in metadata.items() if key not in ['SourceFile', 'File:Directory']}
        self.file_details = result

        return result

    def summarize_results(self):
        return self.file_details


if __name__ == "__main__":
    exif_instance = Exif_Engine()
    pprint(exif_instance.analyze('/home/analyst/packed_exes/unpacked_exe/bitsadmin.exe'))
