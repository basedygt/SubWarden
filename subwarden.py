import json
import requests
import sys
import dns.python

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

  def active_detection(self, subdomain):
    try:
      cname_records = dns.resolver.query(subdomain, "CNAME")
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
      if entry['fingerprint'] in subdomain_content and any(cname in cname_records for cname in entry['cname']) or entry['cname'] == []:
        print(f"[{subdomain}] [{entry['status']}] [{entry['service']}]")
