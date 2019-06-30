import argparse
import lib.utils as utils
import lib.exif as exif
import lib.pe_analysis as pe_analysis
import lib.yara_engine as yara_engine
from pathlib import Path
import os
import pandas as pd
from datetime import datetime

def analyze_file(filepath, yara_rules=None, full_details=False):
    combined_results = {}
    individual_results = []

    # Hashes / Strings
    try:
        individual_results.append(utils.get_strings(filepath=filepath))
        individual_results.append(utils.get_hashes(filepath=filepath))
        individual_results.append(utils.get_type(filepath=filepath))
    except Exception as e:
        individual_results.append({'msg_basic_file_analysis' : 'Basic file analysis error: {}'.format(e)})

    # EXIF
    try:
        exif_instance = exif.Exif_Engine()
        exif_results = exif_instance.analyze(filepath)
        exif_results_renamed = {'exif_{}'.format(key) : value for key, value in exif_results.items()}
        individual_results.append(exif_results_renamed)
    except Exception as e:
        individual_results.append({'msg_exif' : 'Exif result error: {}'.format(e)})

    # PE
    try:
        pe_analyzer = pe_analysis.PEFile(filepath)
        pe_analyzer.analyze()
        pe_results = pe_analyzer.summarize_results()
        pe_results_renamed = {'pe_{}'.format(key) : value for key, value in pe_results.items()}
        individual_results.append(pe_results_renamed)
    except Exception as e:
        individual_results.append({'msg_pe' : 'PE analysis result error: {}'.format(e)})

    # Yara
    try:
        if yara_rules is not None:
            yara_analyzer = yara_engine.Yara_Engine(yara_rules)
            yara_result = yara_analyzer.analyze(filepath)
            yara_result_renamed = {'yara_{}'.format(key): value for key, value in yara_result.items()}
            individual_results.append(yara_result_renamed)
    except Exception as e:
        individual_results.append({'msg_yara' : 'Yara result error: {}'.format(e)})

    for individual_result in individual_results:
        combined_results.update(individual_result)

    return combined_results

def save_data(df, output_path, tag):
    os.makedirs(output_path, exist_ok=True)
    now = datetime.now()
    timestamp = now.isoformat()
    filename = '{}_{}_file_analysis.json.gz'.format(timestamp, tag)
    filepath = os.path.join(output_path, filename)
    df.to_json(filepath, orient='records', lines=True, compression='gzip')


def analyze_directory(directory_path, output_path='./', yara_rules=None, tag=''):
    results = []
    counter = 0
    for filename in Path(directory_path).glob('**/*'):
        filename = str(filename)
        if os.path.isfile(filename):
            result = analyze_file(filename, yara_rules, full_details=False)
            result['filename'] = os.path.basename(filename)
            results.append(result)
            counter += 1
            if counter % 100 == 0:
                # output
                df = pd.DataFrame(results)
                save_data(df, output_path, tag)
                results = []
                counter = 0

    if counter != 0:
        df = pd.DataFrame(results)
        save_data(df, output_path, tag)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parses metadata from files and stores them in log files.')
    parser.add_argument('-d', '--directory', help='Directory containing files to analyze.')
    parser.add_argument('-f', '--file', help='Path to a specific file to analyze.')
    parser.add_argument('-yr', '--yara_rules', help='Path to yara rules to use with analysis.')
    parser.add_argument('-fd', '--full_details', help='Full details will include a large nested json object.')
    parser.add_argument('-o', '--output_directory', help='(Optional) Directory to save parsed data to.  Default is current directory.')
    parser.add_argument('-t', '--tag', help='(Optional) Tag results with this column and include in output filename.')

    args = parser.parse_args()
    yara_rules = None
    if args.yara_rules:
        yara_rules = args.yara_rules

    output_directory = './'
    if args.output_directory:
        output_directory = args.output_directory

    tag = ''
    if args.tag:
        tag = args.tag

    if args.file:
        analyze_file(args.file, yara_rules=yara_rules)

    if args.directory:
        analyze_directory(args.directory, output_directory, yara_rules, tag)
