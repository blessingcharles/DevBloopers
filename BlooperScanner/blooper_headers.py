import requests
from concurrent.futures import ThreadPoolExecutor

from templates.utils import *
from templates.colors import *

headers_details = get_json("/BloopersDb/secHeaders.json")

class BlooperHeaders:

    def __init__(self,urls_list,threads,proxy,timeout,output_file,headers):

        self.urls_list = urls_list
        self.threads = threads
        self.proxy = proxy
        self.timeout = timeout
        self.output_file =output_file
        self.headers = headers
        self.issues = []

    def check(self):
        print(f"{red}\t\t[+] HEADERS SCANNING {reset}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_endpoints , self.urls_list)
        

        output_filename =   self.output_file+"/headers_output.json"
        write_json_to_file(self.issues,output_filename)

        print(f"output-filepath: {grey}[ "+output_filename + " ]\n")
        
        for issue in self.issues:

            print(f"{grey}[+]URL :  {green}{issue['url']}")
            print(f"{grey}[+]NEEDED :" ,end="")
            print_json(issue['needed'])
            print(f"{red}[+]EXPOSED SERVICES :" , end="")
            print_json(issue['bloopers'])


        print(f"[+]{high} check the output file for more info {reset_all}")

    def check_endpoints(self,url):
       # print(url)
        try:
            headers = requests.get(url,proxies=self.proxy,headers=self.headers,timeout=self.timeout).headers
            vuln = {}
            vuln['url'] = url
            vuln['needed'] = []
            vuln['bloopers'] = []

            ## checking for needed headers to harden the security
            for needed_headers in headers_details["needed"]:
                if needed_headers not in headers:
                    
                    vuln['needed'].append(needed_headers)
            
            ## checking for bloopers headers
            for blooper_header in headers_details["bloopers"]:

                if blooper_header in headers:
                    hdict = {blooper_header : headers[blooper_header]}
                    vuln["bloopers"].append(hdict)

            self.issues.append(vuln)
            
          
        except:
            pass

