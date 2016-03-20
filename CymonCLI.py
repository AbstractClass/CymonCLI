import requests
from urllib import parse
import argparse
import pprint
import re
import json


# Initialize variables
root = "https://cymon.io/api/nexus/v1"
http_status_codes = {200: "IP found in database", 404: "IP not found", 429: "Requests throttled", 500: "API error"}
blacklist_options = ["malware", "botnet", "spam", "phishing", "malicious activity", "blacklist", "dnsbl"]
outFile = ""
output = False


# Defining arguments
parser = argparse.ArgumentParser()
parser.add_argument("searchObject", action="store", type=str, help="An IP, Domain, or URL depending on the option")
parser.add_argument("-o", "--output", action="store", default=None, help="Results will be appended to output file")
parser.add_mutually_exclusive_group()
parser.add_argument("-il", "--iplookup", action="store_true",
                    help="Lookup IP address information")
parser.add_argument("-ie", "--ipevents", action="store_true",
                    help="Lookup events related to the IP")
parser.add_argument("-id", "--ipdomain", action="store_true",
                    help="Lookup domains associated with the IP")
parser.add_argument("-iu", "--ipurls", action="store_true", default=None,
                    help="Lookup URLs associated with the IP")
parser.add_argument("-ib", "--ipblacklist", default=None, choices=blacklist_options,
                    help="Retrieve list of IPs associated with the tag")
parser.add_argument("-dl", "--domainlookup", action="store_true",
                    help="Domain lookup for a given name")
parser.add_argument("-db", "--domainblacklist", default=None, choices=blacklist_options,
                    help="Retrieve list of domains associated with the tag")
parser.add_argument("-ul", "--urllookup", action="store", default=None, type=str,
                    help="Get security events for a given URL")


# Parsing arguments
args = parser.parse_args()
search = args.searchObject
try:
    if args.output is not None:
        output = True
        outFile = args.output
except AttributeError as e:
    print("Attr error", e)
    output = False
if args.iplookup:
    url = "{}/ip/{}/".format(root, search)
elif args.ipevents:
    url = "{}/ip/{}/events/".format(root, search)
elif args.ipdomain:
    url = "{}/ip/{}/domains/".format(root, search)
elif args.ipurls:
    url = "{}/ip/{}/urls".format(root, search)
elif args.ipblacklist is not None:
    url = "{}/blacklist/ip/{}/".format(root, args.ib)
elif args.domainlookup:
    url = "{}/domain/{}/".format(root, search)
elif args.domainblacklist is not None:
    url = "{}/blacklist/domain/{}/".format(root, args.db)
elif args.urllookup is not None:
    escaped_url = parse.quote(search, safe='')
    url = "{}/url/{}/".format(root, escaped_url)


# The meat
def get(url, output, outFile):
    header = {"Authorization" : "Token a9f05214f92f2cae3bc3280138f5e73782d154eb"}
    r = requests.get(url, headers=header)
    try:
        r = r.json()
    except:
        return(r)

    ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', url)
    ip = ip[0]
    r['ip'] = ip
    r = json.dumps(r)
    if output:
        with open(outFile, 'a') as out:
            out.write("\n {}".format(r))
    return r


# Screen Output
# pp = pprint.PrettyPrinter(indent=4)
# pp.pprint(get(url, output, outFile))

out = json.loads(get(url, output, outFile))

for key in out:
    print("{} : {}".format(key, out[key]))



