import argparse
import lib.utils as utils
import pandas as pd
from pathlib import Path
import multiprocessing as mp
import os
import math
from statistics import mean
import time
import shutil
import subprocess
from datetime import datetime
import random

# Activate Environment
# C:\Users\analyst\Desktop\venv\pe_analysis\Scripts\activate

# Not Packed:
# python F:\pe_analysis\packer.py -d "E:\data\packed_malware_gatech\benign_cnet_1-15k" -p "none" -o "E:\data\packed_malware_gatech\not_packed" -t F:\pe_analysis\temp_not_packed

# Run APK2
# (pe_analysis) F:\pe_analysis>python F:\pe_analysis\packer.py -d "E:\data\packed_malware_gatech\benign_cnet_1-15k" -p "andpakk2" -o "E:\data\packed_malware_gatech\packed_andpakk2" -t F:\pe_analysis\temp_andpakk2

# Run MEW
# python F:\pe_analysis\packer.py -d "E:\data\packed_malware_gatech\benign_cnet_1-15k" -p "mew" -o "E:\data\packed_malware_gatech\packed_mew" -t F:\pe_analysis\temp_mew

# Run UPX
# python F:\pe_analysis\packer.py -d "E:\data\packed_malware_gatech\benign_cnet_1-15k" -p "upx" -o "E:\data\packed_malware_gatech\packed_upx" -t F:\pe_analysis\temp_upx

def packer_andpakk2(filepath):
    packed_filepath = filepath + '.packed'
    try:
        proc1 = subprocess.Popen(r"C:\packers\ANDpakk2\apk2.exe {} -o {}".format(filepath, packed_filepath))
        time.sleep(30.0)
        proc1.kill()
        time.sleep(1.0)
        if os.path.exists(packed_filepath):
            return packed_filepath
        return ''
    except Exception as e:
        return ''

def packer_aspack(filepath):
    packed_filepath = filepath + '.packed'
    try:
        proc1 = subprocess.Popen(r"C:\packers\aspack\ASPack.exe {} /O{}".format(filepath, packed_filepath))
        #proc1 = subprocess.Popen([r"C:\packers\aspack\ASPack.exe", filepath, "/O", "{}".format(packed_filepath)])
        time.sleep(3.0)
        proc1.kill()
        time.sleep(1.0)
        if os.path.exists(packed_filepath):
            return packed_filepath
        return ''
    except Exception as e:
        return ''

def packer_upx(filepath):
    packed_filepath = filepath + '.packed'
    try:
        proc1 = subprocess.Popen(r"C:\packers\upx\upx.exe -q -o {} {}".format(packed_filepath, filepath))
        time.sleep(5.0)
        proc1.kill()
        time.sleep(1.0)
        if os.path.exists(packed_filepath):
            return packed_filepath
        return ''
    except Exception as e:
        return ''

def packer_mew(filepath):
    '''
    Mew packs the file in place and it might fail, so we need to compare the hash before and after.
    '''
    try:
        orig_hashes = utils.get_hashes(filepath=filepath)
        orig_hash = orig_hashes.get('md5', '')
        print("\nORIGINAL HASH: {}".format(orig_hash))
        print(orig_hashes)
        proc1 = subprocess.Popen(r"C:\packers\MEW\mew11.exe {}".format(filepath))
        time.sleep(15.0)
        proc1.kill()
        time.sleep(1.0)
        new_hashes = utils.get_hashes(filepath=filepath)

        new_hash = new_hashes.get('md5', '')
        print("NEW HASH: {}".format(new_hash))
        print(new_hashes)
        # They are both valid MD5 values, but not equal
        if len(orig_hash) == 32 and len(new_hash) == 32 and orig_hash != new_hash:
            return filepath
        return ''
    except Exception as e:
        return ''

def packer_mpress(filepath):
    '''
    Mpress packs the file in place and it might fail, so we need to compare the hash before and after.
    '''
    try:
        random_options = ['-q', '-q -m', '-q -r', '-q -s', '-q -m']
        selected_option = random_options[random.randint(0, len(random_options))]
        orig_hashes = utils.get_hashes(filepath=filepath)
        orig_hash = orig_hashes.get('md5', '')
        print("\nORIGINAL HASH: {}".format(orig_hash))
        print(orig_hashes)
        proc1 = subprocess.Popen(r"C:\packers\mpress\mpress.exe {} {}".format(selected_option, filepath))
        time.sleep(15.0)
        # Clean up
        proc1.kill()
        time.sleep(1.0)
        new_hashes = utils.get_hashes(filepath=filepath)
        new_hash = new_hashes.get('md5', '')
        print("NEW HASH: {}".format(new_hash))
        print(new_hashes)
        # They are both valid MD5 values, but not equal
        if len(orig_hash) == 32 and len(new_hash) == 32 and orig_hash != new_hash:
            return filepath
        return ''
    except Exception as e:
        return ''


def pack_file(temp_filepath, packer):
    if packer == 'none':
        return temp_filepath
    if packer == 'aspack':
        return packer_aspack(temp_filepath)
    if packer == 'andpakk2':
        return packer_andpakk2(temp_filepath)
    if packer == 'mew':
        return packer_mew(temp_filepath)
    if packer == 'upx':
        return packer_upx(temp_filepath)
    return temp_filepath


def process_file(input_file):
    orig_filepath = input_file.get('filepath', 'none')
    output_dir = input_file.get('output_dir', 'none')
    temp_dir = input_file.get('temp_dir', 'none')
    packer = input_file.get('packer', 'none')
    result = input_file
    input_file_temp_dir = 'none'

    try:
        if not os.path.exists(orig_filepath):
            result['status'] = 'Input file did not exist'
            return result

        # Ensure our directories exist
        base_filename = os.path.basename(orig_filepath)
        input_file_temp_dir = os.path.join(temp_dir, base_filename)
        os.makedirs(input_file_temp_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
        temp_filepath = os.path.join(input_file_temp_dir, base_filename)

        # We either copy the file or unzip it
        if orig_filepath.endswith('.gz'):
            temp_filepath = temp_filepath[:-3]
            utils.decompress_file(orig_filepath, temp_filepath)
        else:
            shutil.copy(orig_filepath, temp_filepath)

        hashes = utils.get_hashes(filepath=temp_filepath)
        orig_hashes = {'orig_{}'.format(key) : value for key, value in hashes.items()}
        result.update(orig_hashes)

        # Call packing routine
        packed_filepath = pack_file(temp_filepath, packer)
        if packed_filepath != '':
            hashes = utils.get_hashes(filepath=packed_filepath)
            packed_hashes = {'packed_{}'.format(key) : value for key, value in hashes.items()}
            result.update(packed_hashes)
            new_packed_filename = '{}.gz'.format(hashes.get('sha256', 'error'))
            new_packed_filepath = os.path.join(output_dir, new_packed_filename)
            utils.compress_file(packed_filepath, new_packed_filepath)
        else:
            result['status'] = 'Failed to pack file: {}'.format(temp_filepath)
            shutil.rmtree(input_file_temp_dir, ignore_errors=False, onerror=None)
            return result

        # Destroy temporary space
        shutil.rmtree(input_file_temp_dir, ignore_errors=False, onerror=None)
        result['status'] = 'Success'

    except Exception as e:
        result['status'] = 'Unrecoverable error: {}'.format(e)
        if input_file_temp_dir != 'none':
            shutil.rmtree(input_file_temp_dir, ignore_errors=False, onerror=None)
        return result

    return result

def process_files(input_dir, packers, output_dir='./output', temp_directory = './temp'):
    all_files = get_files(input_dir)
    batch_run_times = []
    batch_size = 1000
    num_batches = math.ceil(len(all_files) / batch_size)
    start_idx = 0
    end_idx = min(batch_size, len(all_files))

    result_df = pd.DataFrame()

    for packer in packers.split(','):
        packer = packer.strip().lower()
        for i in range(num_batches):
            # Start Timer
            batch_start_timer = time.time()
            print("Batch [{} of {}]".format(i, num_batches))

            # Prepare input for batch
            all_files_batch = all_files[start_idx : end_idx]
            prepared_input = [{'filepath' : filepath, 'temp_dir' : temp_directory, 'output_dir' : os.path.join(output_dir, "{:05d}".format(i)), 'packer' : packer} for filepath in all_files_batch]

            # Kick off batch
            pool = mp.Pool(mp.cpu_count())
            # pool = mp.Pool(1)
            result = pool.map(process_file, prepared_input)
            temp_df = pd.DataFrame(result)
            result_df = pd.concat([result_df, temp_df])
            result_df.to_csv('./partial_all_files_processed.csv', index=False, header=True, encoding='utf-8')

            # Display Status
            batch_total_time = time.time() - batch_start_timer
            batch_run_times.insert(0, batch_total_time)
            average_batch_time = mean(batch_run_times)
            print("{} Batch took {}s, Average Batch time: {}s Expected completion time: {} minutes".format(packer, batch_total_time, average_batch_time, ((num_batches - i)*average_batch_time) / 60))

            # Update start / end indicies
            start_idx += batch_size
            end_idx += batch_size

    print("DONE")
    result_df.to_csv('./{}_{}_all_files_processed.csv'.format(datetime.now().isoformat(), packer), index=False, header=True, encoding='utf-8')
    return result_df
    
def get_files(directory_path):
    all_files = []
    for filename in Path(directory_path).glob('**/*'):
        filename = str(filename)
        if os.path.isfile(filename):
            all_files.append(filename)
    return all_files

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parses metadata from files and stores them in log files.')
    parser.add_argument('-d', '--directory', help='Directory containing files to analyze (will recurse to sub directories).')
    parser.add_argument('-f', '--file', help='Path to a specific file to analyze.')
    parser.add_argument('-o', '--output_directory', help='Base directory where results will be stored.')
    parser.add_argument('-t', '--temp_directory', help='Where temporary work area is created while processing files.')
    parser.add_argument('-p', '--packers', help='Comma separated list of packers to apply, or "all" to run all supported packers')

    args = parser.parse_args()
    if not args.directory:
        print("Must provide an input directory.\n")
        parser.print_help()
        exit()

    if not os.path.exists(args.directory):
        print("Provided input directory does not exist, check your path.\n")
        parser.print_help()
        exit()

    input_directory = args.directory
    temp_directory = './temp'
    packers = 'all'
    output_directory = './output'
    if args.packers:
        packers = args.packers
    if args.output_directory:
        output_directory = args.output_directory
    if args.temp_directory:
        temp_directory = args.temp_directory

    process_files(input_directory, packers, output_directory, temp_directory)
    print("Done!")
