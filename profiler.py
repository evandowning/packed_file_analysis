import argparse
import lib.utils as utils
import lib.exif as exif
import lib.pe_analysis as pe_analysis
import lib.yara_engine as yara_engine
from pathlib import Path
import os
import pandas as pd
from datetime import datetime
from elasticsearch import Elasticsearch
import shutil
import multiprocessing as mp
import math
import time
from statistics import mean

# Process and label MPRESS
# python F:\pe_analysis\profiler.py -d "E:\data\packed_malware_gatech\packed_mpress\00000" -t "E:\data\packed_malware_gatech\temp" -o "E:\data\packed_malware_gatech\profiler_data" -l mpress

def analyze_file(prepared_input):
    combined_results = {}
    filepath = prepared_input['filepath']
    yara_rules = prepared_input.get('yara_rules', None)
    full_details = prepared_input.get('full_details', False)
    temp_path = prepared_input.get('temp_path', './temp')
    label = prepared_input.get('label', 'n/a')

    individual_results = [{'filename' : filepath, 'label' : label}]

    is_gz = False
    if filepath.endswith('.gz'):
        is_gz = True
        temp_path_this_file = os.path.join(temp_path, os.path.basename(filepath))
        os.makedirs(temp_path_this_file, exist_ok=True)
        temp_name = os.path.join(temp_path_this_file, '{}.decompressed'.format(os.path.basename(filepath)))
        utils.decompress_file(filepath, temp_name)
        filepath = temp_name

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

    # Clean up
    if is_gz:
        try:
            shutil.rmtree(temp_path_this_file)
        except Exception as e:
            print("Error removing temp directory: {}".format(e))

    return combined_results

def save_data(df, output_path, label):
    os.makedirs(output_path, exist_ok=True)
    now = datetime.now()
    timestamp = now.isoformat()
    filename = '{}_{}_file_analysis.json.gz'.format(timestamp, label).replace(':','')
    filepath = os.path.join(output_path, filename)
    df.to_json(filepath, orient='records', lines=True, compression='gzip')


def analyze_directory(directory_path, output_path='./', temp_path = './temp', yara_rules=None, label=''):
    results = []
    all_files = [filename for filename in Path(directory_path).glob('**/*')]

    batch_run_times = []
    batch_size = 100
    num_batches = math.ceil(len(all_files) / batch_size)
    start_idx = 0
    end_idx = min(batch_size, len(all_files))

    for i in range(num_batches):
        # Start Timer
        batch_start_timer = time.time()
        print("Batch [{} of {}]".format(i, num_batches))

        # Prepare input for batch
        all_files_batch = all_files[start_idx: end_idx]
        prepared_input = [{'filepath' : str(filepath), 'yara_rules' : yara_rules, 'full_details' : False, 'temp_path' : temp_path, 'label' : label} for filepath in all_files_batch if os.path.isfile(filepath)]

        pool = mp.Pool(mp.cpu_count())
        result = pool.map(analyze_file, prepared_input)
        for entry_idx in range(len(result)):
            entry = result[entry_idx]
            for key, value in entry.items():
                if entry[key] == '':
                    entry[key] = 'n/a'
        results += result

        df = pd.DataFrame(result)
        save_data(df, output_path, label)
        output_to_es(df, clear_index=False)

        # Display Status
        batch_total_time = time.time() - batch_start_timer
        batch_run_times.insert(0, batch_total_time)
        average_batch_time = mean(batch_run_times)
        print("Batch took {}s, Average Batch time: {}s Expected completion time: {} minutes".format(batch_total_time, average_batch_time, ((num_batches - i) * average_batch_time) / 60))

        # Update start / end indicies
        start_idx += batch_size
        end_idx += batch_size



def output_to_es(df, clear_index = False):
    es_host = '127.0.0.1'
    es_port = '9200'
    es_index = 'profiler'
    es_doctype = 'pefile'
    es = Elasticsearch(
        [es_host],
        scheme = 'http',
        port = es_port,
        ca_certs=False,
        verify_certs=False,
        http_compress=True
    )

    if es.ping():
        print("Connected OK.")
    else:
        print("Error connecting to ES.")
        return

    if clear_index:
        es.indices.delete(index=es_index, ignore=[400, 404])

    try:
        df.fillna(0, inplace=True)
        to_delete = [col for col in df.columns.to_list() if col in ['strings_ascii', 'strings_unicode'] or 'msg' in col]
        for col in to_delete:
            del df[col]
        if 'timestamp' not in df.columns.to_list():
            df['@timestamp'] = datetime.now().isoformat()
        records = df.copy().to_dict(orient='records')
        for record in records:
            outcome = es.index(index=es_index, doc_type=es_doctype, body=record)
    except Exception as e:
        print("Error indexing data: {}".format(e))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parses metadata from files and stores them in log files.')
    parser.add_argument('-d', '--directory', help='Directory containing files to analyze.')
    parser.add_argument('-f', '--file', help='Path to a specific file to analyze.')
    parser.add_argument('-t', '--temp_directory', help='Where temporary work area is created while processing files if needed (compressed files).')
    parser.add_argument('-yr', '--yara_rules', help='Path to yara rules to use with analysis.')
    parser.add_argument('-fd', '--full_details', help='Full details will include a large nested json object.')
    parser.add_argument('-o', '--output_directory', help='(Optional) Directory to save parsed data to.  Default is current directory.')
    parser.add_argument('-l', '--label', help='(Optional) Tag results with this column and include in output filename.')

    args = parser.parse_args()
    yara_rules = None
    if args.yara_rules:
        yara_rules = args.yara_rules

    output_directory = './'
    if args.output_directory:
        output_directory = args.output_directory

    temp_directory = './temp'
    if args.temp_directory:
        temp_directory = args.temp_directory

    label = ''
    if args.label:
        label = args.label

    if args.file:
        analyze_file(args.file, yara_rules=yara_rules)

    if args.directory:
        analyze_directory(args.directory, output_directory, temp_directory, yara_rules, label)
