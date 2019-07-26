# Packed File Analysis
The goal of this project is to assess the viability of accurately detecting specific file packers using Machine Learning.  The hypothesis is that a neural network architecture will be able to take in a large number of raw bytes from packed files and learn patterns sufficient for accurate classification without the need for manual feature engineering.
 
## Project Structure
There are three main parts to this project.
1. Profiling PE files.
1. Packing PE files.
1. Multi-class Classifier for packed files.

### 1. Profiling PE Files
Implemented in profiler.py.  Takes in a directory containing files and returns basic file triage information similar to the metadata from VirusTotal.
* File Type (output of file command)
* PE metadata (imports, exports, sections, resources, code signing, strings summary)
* Exif metadata
* Yara rule evaluation

The output is written to a file and sent to a local Elasticsearch instance.
```
usage: profiler.py [-h] [-d DIRECTORY] [-f FILE] [-t TEMP_DIRECTORY]
                   [-yr YARA_RULES] [-fd FULL_DETAILS] [-o OUTPUT_DIRECTORY]
                   [-l LABEL]

Parses metadata from files and stores them in log files.

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Directory containing files to analyze.
  -f FILE, --file FILE  Path to a specific file to analyze.
  -t TEMP_DIRECTORY, --temp_directory TEMP_DIRECTORY
                        Where temporary work area is created while processing
                        files if needed (compressed files).
  -yr YARA_RULES, --yara_rules YARA_RULES
                        Path to yara rules to use with analysis.
  -fd FULL_DETAILS, --full_details FULL_DETAILS
                        Full details will include a large nested json object.
  -o OUTPUT_DIRECTORY, --output_directory OUTPUT_DIRECTORY
                        (Optional) Directory to save parsed data to. Default
                        is current directory.
  -l LABEL, --label LABEL
                        (Optional) Tag results with this column and include in
                        output filename.
```

Example:
```
python profiler.py -d "E:\data\packed_malware_gatech\packed_mpress\00000" -t "E:\data\packed_malware_gatech\temp" -o "E:\data\packed_malware_gatech\profiler_data" -l mpress
```

### 2. Packing PE Files
This functionality was implemented in packer.py 

Packing PE files was implemented in a local Virtual Machine without network access as a precaution.  The operation of this script works as follows:
1. The script needs a directory of the files to pack (it will recursively gather a list all files in the directory and sub-directories).
1. Next it runs multiple processes in parallel, each handling one file.
1. Each original executable is copied to a temporary space, as many of the tools operate off of disk and some overwrite the original file provided.
1. Some checks are performed to confirm the packing appeared to be successful, minimally this is a check that the hash of the file changed.
1. The new file is saved in an output directory provided, with the filename being the same as the new hash value.

```
usage: packer.py [-h] [-d DIRECTORY] [-f FILE] [-o OUTPUT_DIRECTORY]
                 [-t TEMP_DIRECTORY] [-p PACKERS] [-c CPUS]

Parses metadata from files and stores them in log files.

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Directory containing files to analyze (will recurse to
                        sub directories).
  -f FILE, --file FILE  Path to a specific file to analyze.
  -o OUTPUT_DIRECTORY, --output_directory OUTPUT_DIRECTORY
                        Base directory where results will be stored.
  -t TEMP_DIRECTORY, --temp_directory TEMP_DIRECTORY
                        Where temporary work area is created while processing
                        files.
  -p PACKERS, --packers PACKERS
                        Comma separated list of packers to apply, or "all" to
                        run all supported packers
  -c CPUS, --cpus CPUS  Number of processors to run in parallel. Will use all
                        available if not specified.

```

Note: Several of the packers wrote temporary files in places like %TEMP% and the python script continuously attempts to clean any remnants of temp files left behind to avoid filling disk.

Note: a powershell one-liner to kill any WerFault open windows helps keep the desktop tidy.  Recommend running it in the background, as several of the packers fail frequently and display numerous failure popups.

### 3. Classifying PE Files
Implemented in train_model.py


## Results
This proof of concept was initially tested with a dataset of 18k labeled files and five classes ("not packed", "mpress", "UPX", "Aspack", and "andpakk2").  Plan on testing this with a larger dataset with a few hundred thousand files and coverage for at least 10 packing tools in the near future.

![Alt text](plots/accuracy_plot.png "Accuracy Plot")

![Alt text](plots/loss_plot.png "Loss Plot")

![Alt text](plots/confusion_matrix.png "Confusion Matrix")
