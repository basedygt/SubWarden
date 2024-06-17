import json
import requests
import sys
import dns.resolver
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

    def active_detection(self, cname_records, data, subdomain, output_File=None):
        header = {"Accept": "*/*", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"}

        try:
            resp = requests.get(f"https://{subdomain}/", headers=header, allow_redirects=True, verify=False, timeout=5)
        except:
            try:
                resp = requests.get(f"http://{subdomain}/", headers=header, allow_redirects=True, verify=False, timeout=5)
            except:
                return

        subdomain_content = resp.text

        message = None

        for entry in data:
            if entry['fingerprint'] in subdomain_content and entry['fingerprint'] != "":
                if entry['cname'] == []:
                    message = f"[{subdomain}] [{entry['status']}] [{entry['service']}] [BLANK_FP_CNAME]"
                    print(message)
                else:
                    for record in cname_records:
                        for cname_fp in entry['cname']:
                            if str(cname_fp) in str(record):
                                message = f"[{subdomain}] [{entry['status']}] [{entry['service']}]"
                                print(message)
                
                if output_File:
                    if message:
                        with open(output_File, "a") as f:
                            f.write(message + "\n")

    def passive_detection(self, cname_records, subdomain, data, output_File=None):
        for record in cname_records:
            for entry in data:
                if entry['nxdomain']:
                    for cname_fp in entry['cname']:
                        if str(cname_fp) in str(record):
                            try:
                                dns.resolver.resolve(str(record.target))
                                return
                            except dns.resolver.NXDOMAIN:
                                message = f"[{subdomain}] [{entry['status']}] [{entry['service']}] [NXDOMAIN]"
                                print(message)
                                if output_File:
                                    if message:
                                        with open(output_File, "a") as f:
                                            f.write(message + "\n")
                            except:
                                pass

    def detect_Takeover(self, subdomain, data, output_File=None):
        try:
            sub_cname_records = dns.resolver.resolve(subdomain, "CNAME")
        except:
            return

        try:
            self.active_detection(sub_cname_records, data, subdomain, output_File)
            self.passive_detection(sub_cname_records, subdomain, data, output_File)
        except Exception as e:
            print(f"Error for subdomain {subdomain}: {str(e)}")

    def detect_Takeover_threaded(self, max_threads=25, output_File=None):
        data = self._load_Fingerprints()

        with open(self.hosts, "r") as f:
            subdomains = f.read().split("\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for subdomain in subdomains:
                futures.append(executor.submit(self.detect_Takeover, subdomain, data, output_File))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) == 1 or len(sys.argv) > 4 or sys.argv[1] == "help":
        print("""
--------------------------------------------------------
|                                                      |
|                Welcome to SubWarden!                 |
|     A powerful tool by basedygt for detecting        |
|            subdomain takeover risks in Python        |
|                                                      |
--------------------------------------------------------
""")
        print("Usage: python3 subwarden.py <subdomains_file> <output_file> <threads>\n")
        print("Examples:")
        print("  python3 subwarden.py subs.txt")
        print("  python3 subwarden.py subs.txt output.txt")
        print("  python3 subwarden.py subs.txt output.txt 50\n")
    elif len(sys.argv) == 2:
        subwarden(hosts=f"{sys.argv[1]}").detect_Takeover_threaded(output_File=None, max_threads=25)
    elif len(sys.argv) == 3:
        subwarden(hosts=f"{sys.argv[1]}").detect_Takeover_threaded(output_File=f"{sys.argv[2]}", max_threads=25)
    else:
        subwarden(hosts=f"{sys.argv[1]}").detect_Takeover_threaded(output_File=f"{sys.argv[2]}", max_threads=int(sys.argv[3]))
