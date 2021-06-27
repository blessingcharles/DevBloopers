import argparse

def create_parser():

    parser = argparse.ArgumentParser(description="bounty cat")

    parser.add_argument("-u","--url",dest="url",help="enter a valid url")
    parser.add_argument("-f","--file",dest="files",help="enter a file containing urls")
    parser.add_argument("-H" ,"--headers",dest="headers",help="enter headers")
    parser.add_argument("-t","--threads",dest="threads",type=int,default=5,help="enter the number of threads [default 5]")
    parser.add_argument("-p","--proxy",dest="proxy",help="enter a proxy [ip:port]")
    parser.add_argument("--timeout",dest="timeout",type=int,help="enter the timeout for each requests [default 5 seconds]",default=5)
    parser.add_argument("-o","--output",dest="output",help="enter the directory name to store the outputs",default="devbloopers_output")
    parser.add_argument("-d","--delay",dest="delay",type=int,help="enter delay between each vuln scan checking [ default 1 ]",default=1)
    parser.add_argument("--blooper-headers",dest="check_headers",action="store_true",help="check any misconfigurations in the headers present [default false]",default=False)


    return parser
