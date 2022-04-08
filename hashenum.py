#!/usr/bin/python3
import base64
from itertools import permutations
import hashlib
import argparse

__author__ = 'https://github.com/vegkva'


description_text = """Script that makes permutations of words in the specified wordlist
and encodes the permutations with the specified encoding type. Then the provided
encoded data is compared to each of these permutations, and returns the corresponding
plaintext if there is a match"""

example_text = """Examples:\npython hashenum.py personal_data md5 6f4771b11509fa7c7c11077f18cda27d
abc
"""

hash_len = {'md5': 32, 'sha1': 40, 'sha224': 56, 'sha256': 64, 'sha512': 128}
hash_types = ['md5','sha1', 'sha224', 'sha256', 'sha512', 'base64']
wordlist = []
dic = {}


parser = argparse.ArgumentParser(description=description_text, usage='%(prog)s [options]',
                                 epilog=example_text, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('wordlist', metavar='wordlist', type=str, help='text file of words to create permutations off from')
parser.add_argument('encoding', metavar='encoding', type=str,
                    help="""Available encodings: \n['md5','sha1', 'sha224', 'sha256', 'sha512', 'base64']""")
parser.add_argument('string', metavar='encoded_string', type=str, help='the encoded string (hash, base64) to compare')

args = parser.parse_args()
string_to_check = args.string
encoding = args.encoding
text_file = args.wordlist

# Function to make sure that the provided
# hash is in fact hexadecimal
def check_string(string_to_check):
    if encoding != "base64":
        try:
            int(string_to_check, 16)
        except ValueError as e:
            print(e)
            print(f"{string_to_check} doesn't appear to be a hash")
            exit(1)
        if encoding not in hash_types:
            print(f"Error: Hash type must be one of these ['md5', 'sha1', 'sha224', 'sha256', 'sha512'], was {encoding}")
            exit(1)
        elif encoding != "base64" and not check_length(string_to_check, encoding, hash_len[encoding]):
            print(f"Error: Are you sure '{string_to_check}' is '{encoding}'\n")
            print(f"Number of digits in {string_to_check} = {len(string_to_check)}")
            print(f"Number of digits required in {encoding} = {hash_len[encoding]}")
            exit(1)


# add words from text file into a list
try:
    with open(text_file, 'r') as f:
        wordlist += f.read().split()
except FileNotFoundError:
    print(f"'{text_file}' not found")
    exit(1)


def check_length(str, type, n):
    if type == "md5":
        return len(str) == n
    if type == "sha1":
        return len(str) == n
    if type == "sha224":
        return len(str) == n
    if type == "sha256":
        return len(str) == n
    if type == "sha512":
        return len(str) == n


check_string(string_to_check)


for r in range(len(wordlist) + 1):
    # create the permutations
    p = permutations(wordlist, r)

    # add plaintext and encoded plaintext into a dictionary
    for i in p:
        a = ""
        for k in i:
            a += k
        if a != "":
            if encoding == "md5":
                dic[a] = hashlib.md5(a.encode()).hexdigest()
            elif encoding == "sha1":
                dic[a] = hashlib.sha1(a.encode()).hexdigest()
            elif encoding == "sha224":
                dic[a] = hashlib.sha224(a.encode()).hexdigest()
            elif encoding == "sha256":
                dic[a] = hashlib.sha256(a.encode()).hexdigest()
            elif encoding == "sha384":
                dic[a] = hashlib.sha384(a.encode()).hexdigest()
            elif encoding == "sha512":
                dic[a] = hashlib.sha512(a.encode()).hexdigest()
            elif encoding == "base64":
                dic[a] = base64.b64encode(a.encode()).decode()

    for key, value in dic.items():
        if string_to_check == value:
            print(f"Found matching {encoding} hash: {key, value}")
            exit(1)
print(f"No match found for {encoding} hash: {string_to_check}")
exit(1)

