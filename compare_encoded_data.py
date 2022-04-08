#!/usr/bin/python3
import base64, re, hashlib, argparse, datetime
from itertools import permutations

__author__ = 'https://github.com/vegkva'

start = datetime.datetime.now()

description_text = """
\tScript that creates permutations of all strings in the specified 
\ttext file. The permutations are encoded with the specified encoding type, 
\tand added to a dictionary containing the current 'key,value-pair' 
\tpermutation and their corresponding encoding. 

\tThen the provided encoded string is compared to the current 'key,value-pair' in the 
\tdictionary. If there is a match, the script prints the corresponding plaintext.
\tOtherwise, the 'key,value-pair' is deleted from the dictionary.
"""

example_text = """
Examples:\n\tpython compare_encoded_data.py text_file md5 6f4771b11509fa7c7c11077f18cda27d
\tpython compare_encoded_data.py text_file base64 SGFuc2VuMTY0OTM1OTkyNE9sZQ==
"""

hash_len = {'md5': 32, 'sha1': 40, 'sha224': 56, 'sha256': 64, 'sha512': 128}
hash_types = ['md5','sha1', 'sha224', 'sha256', 'sha512', 'base64']
list_of_strings = []
dic = {}


parser = argparse.ArgumentParser(description=description_text,
                                 epilog=example_text, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('textfile', metavar='text_file', type=str, help="text file to create permutations from")
parser.add_argument('encoding', metavar='encoding', type=str,
                    help="Available encodings: \n['md5', 'sha1', 'sha224', 'sha256', 'sha512', 'base64']")
parser.add_argument('string', metavar='encoded_string', type=str, help='the encoded string to be compared')
parser.add_argument('remove_duplicates', metavar='remove_duplicates', type=str, help='remove duplicates in text file: y/n')
args = parser.parse_args()
string_to_check = args.string
encoding = args.encoding
text_file = args.textfile
remove_duplicates = args.remove_duplicates

# Function to make sure that the provided
# hash is in fact hexadecimal and the length
# is correct according to chosen hash
def check_hash(string_to_check):
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


# add strings from text file into a list
# either with or without duplicates
try:
    with open(text_file, 'r') as f:
        if remove_duplicates.lower() == "y":
            # create a set to remove duplicates
            list_of_strings = set(re.split("\.? |\.\n|,? |,\n|;? |;|:? |:|\*|\n+| ", f.read()))
        else:
            list_of_strings = re.split("\.? |\.\n|,? |,\n|;? |;|:? |:|\*|\n+| ", f.read())
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


check_hash(string_to_check)


for r in range(len(list_of_strings) + 1):
    # create the permutations
    p = permutations(list_of_strings, r)

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

            for key, value in list(dic.items()):
                if string_to_check == value:
                    stop = datetime.datetime.now()
                    elapsed = stop - start
                    print(f"Found matching {encoding}: {key, value}")
                    print(f"Time elapsed: {elapsed.seconds // 3600}hrs:{elapsed.seconds // 60}min:{elapsed.seconds}sec:{elapsed.microseconds//1000}ms")
                    exit(1)
                else:
                    del dic[key]

stop = datetime.datetime.now()
elapsed = stop-start
print(f"No match found for {encoding}: '{string_to_check}'")
print(f"Time elapsed: {elapsed.seconds // 3600}hrs:{elapsed.seconds // 60}min:{elapsed.seconds}sec:{elapsed.microseconds//1000}ms")
exit(1)



