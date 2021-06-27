from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from templates.requester import requester
from templates.utils import get_json, print_json, write_json_to_file
from templates.colors import *
import time

cors_details = get_json("/BloopersDb/cors.json")

class Cors:
    
    def __init__(self,urls_list,threads,proxy,timeout,output_file,headers,delay):
        
        self.urls_list = urls_list
        self.threads = threads
        self.proxy = proxy
        self.timeout = timeout
        self.output_file =output_file
        self.headers = headers
        self.issues = []
        self.delay = delay
        
    def start(self):
        print(f"{green}\t\tCORS SCANNING RESULTS")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_endpoints , self.urls_list)

        # things without threads : (
        # for url in self.urls_list:
        #     self.check_endpoints(url)
        
        output_file_name = self.output_file + "/cors_output.json"
        write_json_to_file(self.issues,output_file_name)

        print(f"output-filepath{grey}[ "+output_file_name + " ]\n")
        
        for issue in self.issues:
            print(f"{blue}[+]URL :           {green}{issue['url']}")
            print(f"[+]{blue}vulnerability : {green}{issue['vulnerability']}")
            print(f"[-]{blue}severity :        {red}{issue['severity']}")
            print(f"[-]{blue}exploitation :   {grey}{issue['exploitation']}{reset}\n")

        print(f"[+]{high} check the output file for more info {reset_all}")
    def check_endpoints(self,url):

        self.reflect_origin(url)
        time.sleep(self.delay)

        self.null_origin(url)
        time.sleep(self.delay)

        self.prefix_scan(url)
        time.sleep(self.delay)

        self.suffix_scan(url)
        time.sleep(self.delay)

        self.http_trust(url)
        time.sleep(self.delay)

        self.special_chars(url)
        time.sleep(self.delay)

        self.trust_all_origin(url)

        

    #ACAO : example.com_.attacker.com

    ### Example Apache configuration
    '''
        SetEnvIf Origin "^https?:\/\/(.*\.)?xxe.sh([^\.\-a-zA-Z0-9]+.*)?" AccessControlAllowOrigin=$0
        Header set Access-Control-Allow-Origin %{AccessControlAllowOrigin}e env=AccessControlAllowOrigin
    '''

    # underscore supported by all browsers

    def special_chars(self,url):
        try:
            domain = urlparse(url).netloc
            
            origin = f"{domain}_.example.com"

            res_headers = requester(url=url,headers=self.headers,time=self.timeout,proxy=self.proxy,origin=origin).headers

            if res_headers:
                acao_header, acac_header = res_headers.get('access-control-allow-origin', None), res_headers.get('access-control-allow-credentials', None)
                if acao_header and acao_header == origin:
                    vulnerability = cors_details['underscore']
                    vulnerability['url'] = url
                    vulnerability['vulnerability'] = 'underscore regex failed'
                    vulnerability['access-control-allow-origin'] = acao_header
                    vulnerability['acces-control-allow-credentials'] = acac_header

                    self.issues.append(vulnerability)
        except:
            pass

    # ACAO : null
    def null_origin(self,url):
        try:
            origin = "example.com"
            res_headers = requester(url=url,headers=self.headers,time=self.timeout,proxy=self.proxy,origin=origin).headers

            if res_headers:
                acao_header, acac_header = res_headers.get('access-control-allow-origin', None), res_headers.get('access-control-allow-credentials', None)
                if acao_header and acao_header == 'null':
                    vulnerability = cors_details['null']
                    vulnerability['url'] = url
                    vulnerability['vulnerability'] = 'null origin'
                    vulnerability['access-control-allow-origin'] = acao_header
                    vulnerability['acces-control-allow-credentials'] = acac_header

                    self.issues.append(vulnerability)
        except:
            pass
    
    # ACAO : vulnerable.com.attacker.com and vulnerable.comattacker.com
    def prefix_scan(self,url):

        domain = urlparse(url).netloc
          
        try:  
            origin = f"{domain}.example.com"
            res_headers = requester(url=url,headers=self.headers,time=self.timeout,proxy=self.proxy,origin=origin).headers

            if res_headers:
                acao_header, acac_header = res_headers.get('access-control-allow-origin', None), res_headers.get('access-control-allow-credentials', None)
                if acao_header and acao_header == origin:
                    vulnerability = cors_details['prefix match']
                    vulnerability['url'] = url
                    vulnerability['vulnerability'] = 'prefix match'
                    vulnerability['access-control-allow-origin'] = acao_header
                    vulnerability['acces-control-allow-credentials'] = acac_header

                    self.issues.append(vulnerability)
        except:
            pass
                
        
        try:
            origin = f"{domain}example.com"
            res_headers = requester(url=url,headers=self.headers,time=self.timeout,proxy=self.proxy,origin=origin).headers

            if res_headers:
                acao_header, acac_header = res_headers.get('access-control-allow-origin', None), res_headers.get('access-control-allow-credentials', None)
                if acao_header and acao_header == origin:
                    vulnerability = cors_details['prefix match']
                    vulnerability['exploitation'] = "Make requests from vulnerable.com<your-domain>.com"
                    vulnerability['url'] = url
                    vulnerability['vulnerability'] = 'prefix match'
                    vulnerability['access-control-allow-origin'] = acao_header
                    vulnerability['acces-control-allow-credentials'] = acac_header

                    self.issues.append(vulnerability)
        except:
            pass   


    # ACAO : attackerexample.com
    def suffix_scan(self,url):
        try:
            domain = urlparse(url).netloc
            
            origin = f"example{domain}"
            res_headers = requester(url=url,headers=self.headers,time=self.timeout,proxy=self.proxy,origin=origin).headers

            if res_headers:
                acao_header, acac_header = res_headers.get('access-control-allow-origin', None), res_headers.get('access-control-allow-credentials', None)
                if acao_header and acao_header == origin:
                    vulnerability = cors_details['suffix match']
                    vulnerability['url'] = url
                    vulnerability['vulnerability'] = 'suffix match'
                    vulnerability['access-control-allow-origin'] = acao_header
                    vulnerability['acces-control-allow-credentials'] = acac_header

                    self.issues.append(vulnerability)
        except:
            pass
    

    def trust_all_subdomains(self,url):

        try:
            domain = urlparse(url).netloc
            
            origin = f"example.{domain}"
            res_headers = requester(url=url,headers=self.headers,time=self.timeout,proxy=self.proxy,origin=origin).headers

            if res_headers:
                acao_header, acac_header = res_headers.get('access-control-allow-origin', None), res_headers.get('access-control-allow-credentials', None)
                if acao_header and acao_header == origin:
                    vulnerability = cors_details['subdomains']
                    vulnerability['url'] = url
                    vulnerability['vulnerability'] = 'subdomains'
                    vulnerability['access-control-allow-origin'] = acao_header
                    vulnerability['acces-control-allow-credentials'] = acac_header

                    self.issues.append(vulnerability)
        except:
            pass


    # wildcard ACAO : *
    def trust_all_origin(self,url):
        
        try:
            origin = "example.com"
            res_headers = requester(url=url,headers=self.headers,time=self.timeout,proxy=self.proxy,origin=origin).headers

            if res_headers:
                acao_header, acac_header = res_headers.get('access-control-allow-origin', None), res_headers.get('access-control-allow-credentials', None)
                if acao_header and acao_header == '*':
                    vulnerability = cors_details['all origin']
                    vulnerability['url'] = url
                    vulnerability['vulnerability'] = 'trust all origin'
                    vulnerability['access-control-allow-origin'] = acao_header
                    vulnerability['acces-control-allow-credentials'] = acac_header

                    self.issues.append(vulnerability)   
        except:
            pass 


    # Reflect what given in origin header
    # ACAO : attacker.com
    def reflect_origin(self,url):
        try:
            origin = "example.com"
            res_headers = requester(url=url,headers=self.headers,time=self.timeout,proxy=self.proxy,origin=origin).headers

            if res_headers:
                acao_header, acac_header = res_headers.get('access-control-allow-origin', None), res_headers.get('access-control-allow-credentials', None)
                if acao_header and acao_header == origin:
                    vulnerability = cors_details['reflected']
                    vulnerability['url'] = url
                    vulnerability['vulnerability'] = 'reflect origin'
                    vulnerability['access-control-allow-origin'] = acao_header
                    vulnerability['acces-control-allow-credentials'] = acac_header

                    self.issues.append(vulnerability)
        except:
            pass

    
    #ACAO : http://example.com
    def http_trust(self,url):

        try:
            domain = urlparse(url).netloc
            
            origin = f"http://{domain}"
            res_headers = requester(url=url,headers=self.headers,time=self.timeout,proxy=self.proxy,origin=origin).headers

            if res_headers:
                acao_header, acac_header = res_headers.get('access-control-allow-origin', None), res_headers.get('access-control-allow-credentials', None)
                if acao_header and acao_header.startswith("http://"):
                    vulnerability = cors_details['http']
                    vulnerability['url'] = url
                    vulnerability['vulnerability'] = 'http allowance'
                    vulnerability['access-control-allow-origin'] = acao_header
                    vulnerability['acces-control-allow-credentials'] = acac_header
                    self.issues.append(vulnerability)
        except:
            pass
    
   




