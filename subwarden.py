import json
import requests
import sys
import dns.resolver
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class subwarden:

  def __init__(self, hosts):
    self.hosts = hosts

  def _load_Fingerprints(self):
    try:
      resp = requests.get("https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json", timeout=5)
      data = resp.json()
    except Exception as e:
      print(f"Unable to load fingerprints: {str(e)}")
      sys.exit(1)
    
    return data

  def active_detection(self, subdomain, output_File=None):
    try:
      cname_records = dns.resolver.resolve(subdomain, "CNAME")
    except:
      return

    header = {"Accept": "*/*", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"}

    try:
      resp = requests.get(f"https://{subdomain}/", headers=header, allow_redirects=True, verify=False, timeout=5)
    except:
      try:
        resp = requests.get(f"http://{subdomain}/", headers=header, allow_redirects=True, verify=False, timeout=5)
      except:
        return

    subdomain_content = resp.text
    data = self._load_Fingerprints()

    for entry in data:
      if entry['fingerprint'] in subdomain_content and entry['fingerprint'] != "":
        if entry['cname'] == []:
          message = f"[{subdomain}] [{entry['status']}] [{entry['service']}] [BLANK_FP_CNAME]"
          print(message)
        else:
          for record in cname_records:
            for cname_fp in entry['cname']:
              if re.search(re.escape(record), cname_fp):
                message = f"[{subdomain}] [{entry['status']}] [{entry['service']}]"
                print(message)
  
        if output_File:
          if message:
            with open(output_File, "a") as f:
              f.write(message + "\n")

if __name__ == "__main__":
  subwarden(hosts="foobar").active_detection(subdomain="sub.example.com")
