from logging import exception
import requests
from requests.api import head
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def requester(url,headers,time,origin,GET=True,POST=False,proxy=None):

  #  print(url)
    headers['Origin'] = origin

    try:
   
        if GET:
            page = requests.get(url,timeout=time,proxies=proxy , verify=False,headers=headers)
            return page

        if POST:
            page = requests.post(url,timeout=time)
            return page
    except exception as e:

        pass
