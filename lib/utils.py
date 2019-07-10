try:
    import magic
except:
    from winmagic import magic
import hashlib
import subprocess
from statistics import mean, stdev
import math
from collections import Counter
import gzip

def compress_file(input_filepath, output_filepath):
    try:
        input = open(input_filepath, 'rb')
        file_content = input.read()
        input.close()
    except Exception as e:
        return "Could not read file: {}: {}".format(input_filepath, e)

    try:
        output = gzip.GzipFile(output_filepath, 'wb')
        output.write(file_content)
        output.close()
    except Exception as e:
        return "Could not write gzipped file: {}: {}".format(output_filepath, e)

    return "success"

def decompress_file(input_filepath, output_filepath):
    try:
        input = gzip.GzipFile(input_filepath, 'rb')
        file_content = input.read()
        input.close()
    except Exception as e:
        return "Could not read gzipped file: {}: {}".format(input_filepath, e)

    try:
        output = open(output_filepath, 'wb')
        output.write(file_content)
        output.close()
    except Exception as e:
        return "Could not write file: {}: {}".format(output_filepath, e)

    return "success"

def get_entropy(text):
    freq_counts = Counter(text)
    length = float(len(text))
    entropy = -sum(count/length * math.log(count/length, 2) for count in freq_counts.values())
    return entropy


def get_type(filepath=None, buffer=None):
    filetype = {'file_type' : 'unknown'}
    try:
        if filepath is not None:
            filetype['file_type'] = magic.from_file(filepath)
        elif buffer is not None:
            filetype['file_type'] = magic.from_buffer(buffer)
        else:
            filetype['file_type'] = 'Invalid input: buffer and filepath are None'
    except Exception as e:
        filetype['file_type'] = 'Error: {}'.format(e)

    return filetype


def get_hashes(filepath=None, buffer=None):
    hashes = {'sha256' : '', 'sha1' : '', 'md5' : '', 'file_size' : '', 'msg' : 'OK'}
    try:
        if filepath is not None:
            fh = open(filepath, 'rb')
            data = fh.read()
            fh.close()
        elif buffer is not None:
            data = buffer
        else:
            hashes['msg'] = 'Invalid input: buffer and filepath are None'
            return hashes

        hashes['file_size'] = len(data)
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['md5'] = hashlib.md5(data).hexdigest()
    except Exception as e:
        hashes['msg'] = 'Error: {}'.format(e)
    return hashes

def basic_stats(numeric_list):
    '''
    Given a list, safetly computes the min, max, mean, and standard deviation.  Returns 0, when not enough values for the computation are present in the list.
    :param numeric_list:
    :return:
    '''
    try:
        if numeric_list is None or not isinstance(numeric_list, list):
            return 0, 0, 0, 0
        if len(numeric_list) == 0:
            return 0, 0, 0, 0
        if len(numeric_list) == 1:
            val = numeric_list[0]
            return val, val, val, 0
        return min(numeric_list), max(numeric_list), mean(numeric_list), stdev(numeric_list)
    except:
        return 0, 0, 0, 0


def get_strings(filepath=None, verbose=False):
    strings = {'strings_unicode' : '',
               'strings_ascii' : '',
               'strings_unicode_cnt' : 0,
               'strings_unicode_len_avg': 0,
               'strings_unicode_len_std': 0,
               'strings_unicode_entropy': 0,
               'strings_ascii_cnt': 0,
               'strings_ascii_len_avg': 0,
               'strings_ascii_len_std': 0,
               'strings_ascii_entropy': 0
               }

    try:
        # Check version of strings being used:
        menu = subprocess.Popen(['strings', '--help'], stdout=subprocess.PIPE).communicate()[0]
        if '-nobanner' in menu.decode('utf-8'):
            # Windows version
            ascii_bytes = subprocess.Popen(['strings', filepath], stdout=subprocess.PIPE).communicate()[0]
            unicode_bytes = subprocess.Popen(['strings', '-u', '-nobanner', filepath], stdout=subprocess.PIPE).communicate()[0]
        else:
            ascii_bytes = subprocess.Popen(['strings', filepath], stdout=subprocess.PIPE).communicate()[0]
            unicode_bytes = subprocess.Popen(['strings', '-el', filepath], stdout=subprocess.PIPE).communicate()[0]

        unicode_strings = unicode_bytes.decode('utf-8')
        ascii_strings = ascii_bytes.decode('utf-8')

        if verbose:
            strings['strings_ascii'] = ascii_strings
            strings['strings_unicode'] = unicode_strings

        ascii_strings_lengths = [len(text) for text in ascii_strings.split('\n')]
        unicode_strings_lengths = [len(text) for text in unicode_strings.split('\n')]
        strings['strings_ascii_cnt'] = len(ascii_strings_lengths)
        strings['strings_unicode_cnt'] = len(unicode_strings_lengths)
        strings['strings_ascii_len_avg'] = mean(ascii_strings_lengths)
        strings['strings_unicode_len_avg'] = mean(unicode_strings_lengths)
        try:
            strings['strings_ascii_len_std'] = stdev(ascii_strings_lengths)
        except:
            strings['strings_ascii_len_std'] = -1

        try:
            strings['strings_unicode_len_std'] = stdev(unicode_strings_lengths)
        except:
            strings['strings_unicode_len_std'] = -1

        strings['strings_ascii_entropy'] = get_entropy(ascii_strings)
        strings['strings_unicode_entropy'] = get_entropy(unicode_strings)

    except Exception as e:
        strings['msg'] = 'Error: {}'.format(e)

    return strings
