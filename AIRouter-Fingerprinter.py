# Copyright 2024 Photubias(c)
# Copyright 2026 at3mic

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.     
   
import optparse, requests, os
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

iTimeout = 10

dicHeaders = {'User-Agent' : r'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36', 'Content-Type': 'application/json'}
nineRouterHeaders = {'Content-Type': 'application/json', 'password': '123456'}

def fingerPrint(listArgs):
    (sURL, sProxy, boolVulns, boolOnly9Router, boolOnlyOmniRoute) = listArgs
    def getPage(passedURL):
        try:
            if sProxy: oResponse = requests.get(passedURL, verify=False, proxies={'https':sProxy}, headers = dicHeaders, timeout = iTimeout)
            else: oResponse = requests.get(passedURL, verify=False, headers = dicHeaders, timeout = iTimeout)
            return oResponse
        except:
            return None

    # 9Router
    if boolOnly9Router or not boolOnlyOmniRoute:
        oResponse = getPage(f"{sURL}/login")
        if oResponse and oResponse.status_code == 200:
            if '9Router - AI Infrastructure Management' in oResponse.text:
                sVersion = requests.get(f"{sURL}/api/version", verify=False, proxies={'https':sProxy}, headers = dicHeaders, timeout = iTimeout).json()["currentVersion"]
                sDefaultPassword = "success" in requests.post(f"{sURL}/api/auth/login", verify=False, proxies={'https':sProxy}, headers = nineRouterHeaders, timeout = iTimeout).text
                print(f'🤖 [+] {sURL}: 9Router, version {sVersion}')
                sVersionTuple = tuple(map(int, sVersion.split(".")))
                if boolVulns:
                    if (0, 2, 21) <= sVersionTuple <= (0, 4, 41):
                        print(f'  ⚠️  [!] {sURL} (9Router) is vulnerable to hardcoded JWT!')
                    if sDefaultPassword:
                        print(f'  🔑  [!] {sURL} (9Router) has the default password!')
            return
    
    # OmniRoute
    # TODO: Modify for OmniRoute
    # if boolOnlyOmniRoute or not boolOnly9Router:
    #     oResponse = getPage(f"{sURL}/login")
    #     if oResponse and oResponse.status_code == 200:
    #         if '9Router - AI Infrastructure Management' in oResponse.text:
    #             sVersion = requests.get(f"{sURL}/api/version").json()["currentVersion"]
    #             sDefaultPassword = "success" in requests.post(f"{sURL}/api/auth/login", verify=False, proxies={'https':sProxy}, headers = nineRouterHeaders, timeout = iTimeout).text
    #             print(f'🤖 [+] {sURL}: 9Router, version {sVersion}')
    #             sVersionTuple = tuple(map(int, sVersion.split(".")))
    #             if boolVulns:
    #                 if (0, 2, 21) <= sVersionTuple <= (0, 4, 41):
    #                     print(f'  ⚠️ [!] {sURL} (9Router) is vulnerable to hardcoded JWT!')
    #                 if sDefaultPassword:
    #                     print(f'  🔑 [!] {sURL} (9Router) has the default password!')
    #         return

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for sLine in lstLines:
        lstIPs.append(sLine)
    return lstIPs

def main():
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs enumeration of AI routers on a given URL\n'
              'When provided with the --scanvulns parameter it spits out vulnerabilities based on the version.')

    parser = optparse.OptionParser(usage = sUsage)
    parser.add_option('--threads', '-t', metavar='INT', dest='threads', default = 64, help='Amount of threads. Default 64')
    parser.add_option('--scanvulns', '-s', dest='vulns', action='store_true', help='Check for common vulnerabilities.', default=False)
    parser.add_option('--proxy', '-p', metavar='STRING', dest='proxy', help='HTTP proxy (e.g. 127.0.0.1:8080), optional')
    parser.add_option('--only-9router', '-9', dest='only9', action='store_true', help='Only check IPs for 9Router', default=False)
    parser.add_option('--only-omniroute', '-o', dest='onlyo', action='store_true', help='Only check IPs for OmniRoute', default=False)

    (options,args) = parser.parse_args()
    if not args or not len(args) == 1:
        sURLInput = input('[?] Please enter the URL to scan [http://localhost:20128]: ')
        if not sURLInput:
            sURLInput = "http://localhost:20128"
        lstURLs = [sURLInput]
    else:
        if os.path.isfile(args[0]):
            print(f'[+] Parsing file {args[0]} for URLs.')
            lstURLs = getIPsFromFile(args[0])
    oPool = ThreadPool(int(options.threads))
    print(f'[!] Scanning {len(lstURLs)} addresses using up to {options.threads} threads.')
    oPool.map(fingerPrint, zip(lstURLs, repeat(options.proxy), repeat(options.vulns), repeat(options.only9), repeat(options.onlyo)))
    return

if __name__ == "__main__":
    main()
