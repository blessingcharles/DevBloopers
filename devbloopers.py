import sys
import time
import click

from BlooperScanner.cors import Cors
from BlooperScanner.blooper_headers import BlooperHeaders

from templates.colors import *
from templates.banner import banner , print_line
from templates.create_directory import dir_create
from templates.utils import input_from_stdin , input_from_file , default_headers
from templates.cmdline_parse import create_parser
import templates.HandleSignals 

class DevBloopers:
    
    def __init__(self,urls_list,threads,proxy,timeout,output_file,headers,delay):
        
        self.urls_list = urls_list
        self.threads = threads
        self.proxy = proxy
        self.timeout = timeout
        self.output_file =output_file
        self.headers = headers
        self.delay = delay

    def check_cors(self):
       
        cors_scanner = Cors(self.urls_list , self.threads , self.proxy ,self.timeout, self.output_file , self.headers , self.delay)
        cors_scanner.start()
        
    def check_headers(self):

        ch = BlooperHeaders(self.urls_list , self.threads , self.proxy ,self.timeout, self.output_file , self.headers )
        ch.check()


if __name__ == "__main__":
    
    start = time.time()
    banner(blue,reset)
    print_line(red,reset)

    parser = create_parser().parse_args()
    
    url = parser.url
    urls_file = parser.files
    headers = parser.headers if parser.headers is not None else default_headers
    threads = parser.threads
    proxy = {'http':parser.proxy , 'https':parser.proxy } if parser.proxy is not None else None
    timeout = parser.timeout
    output_file = parser.output   
    delay = parser.delay
    is_check_headers = parser.check_headers

    urls_list = []

    if url : urls_list.append(url)

    #take input from stdin pipe
    if not sys.stdin.isatty():
        urls_list = input_from_stdin()

    #take urls from file
    if urls_file:
        print(f"{green}urls file provided : "+ urls_file + reset)

        urls_list = urls_list + input_from_file(urls_file)
        
    if  not url and not urls_list:
        print(f"{red}ENTER A VALID INPUT [URL OR URLS CONTAINING FILE] \n TRY python3 bounty_cat.py --help{reset}")
        quit()

    
    output_file = sys.path[0]+"/"+output_file
    dir_create(output_file)
    

    #just cheems ; )
    bloomper = DevBloopers(urls_list,threads,proxy,timeout,output_file,headers,delay)
    
    # checking for security headers misconfiguration
    if is_check_headers:

        bloomper.check_headers()
    
    if not is_check_headers:
        # checking for cors misconfiguration
        bloomper.check_cors()


        # JUST BENCHMARKING STUFFS
    end = time.time()
    print(f"{green}[+]TOTAL TIME TAKEN--->{reset} {round(end-start)}sec")

