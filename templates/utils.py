import sys
import os
from .colors import *
import json


default_headers = {'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0',
                'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language' : 'en-US,en;q=0.5',
                'Accept-Encoding' : 'gzip, deflate',
                'Upgrade-Insecure-Requests' : '1'}


def input_from_stdin():

    urls_list = []

    for line in sys.stdin:
        if line.startswith("http") or line.startswith("https") :
            urls_list.append(line.strip())
    
    return urls_list


def input_from_file(file_name):

    file_contents = []

    if not os.path.exists(file_name):
        print(f"{red}unable to locate {file_name} {reset}")
        quit()
        
    with open(file_name,  'r') as f:
        for line in f.readlines():
            file_contents.append(line.strip())

    return file_contents 

def print_json(mydict):
    
    print(blue)
    print(json.dumps(mydict,indent=4))
    print(reset)

def write_json_to_file(mydict , output_filename):

    json_object = json.dumps(mydict, indent = 4)
  
        # Writing to sample.json
    with open(output_filename, "w") as outfile:
        outfile.write(json_object)


def get_json(file):

    with open(sys.path[0]+file) as f:
        return json.load(f)

