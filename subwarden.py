import json
import requests
import sys
import dns.resolver
import re
import urllib3
import concurrent.futures

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

  def active_detection_threaded(self, max_threads=10, output_File=None):
    with open(self.hosts, "r") as f:
      subdomains = f.read().split("\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
      futures = []
      for subdomain in subdomains:
        futures.append(executor.submit(self.active_detection, subdomain, output_File))
      
      for future in concurrent.futures.as_completed(futures):
        try:
          future.result()
        except Exception as e:
          print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
  if len(sys.argv) != 4 or sys.argv[1] == "help":
    print("""
--------------------------------------------------------
|                                                      |
|                Welcome to SubWarden!                 |
|     A powerful tool by basedygt for detecting        |
|            subdomain takeover risks in Python        |
|                                                      |
--------------------------------------------------------
""")
    print("Usage: python3 subwarden.py <subdomains_file> <output_file> <threads>")
    print("Example:")
    print("        python3 subwarden.py subs.txt output.txt")
    print("        python3 subwarden.py subs.txt output.txt 20\n")
  else:
    subwarden(hosts=f"{sys.argv[1]}").active_detection_threaded(output_File=f"{sys.argv[2]}", max_threads=int(sys.argv[3]))
