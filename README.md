### Checklist

- [x] Active detection via matching vulnerable fingerprints served on web content and `cname` records
- [x] Passive detection via matching `nxdomain` fingerprints in `cname` records
- [x] Auto update and use latest Fingerprints from [can-i-takeover-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- [ ] Use more fingerprints from external sources
- [ ] Detect additional DNS misconfiguration such as A records

### Usage

```
$ python3 subwarden.py help

--------------------------------------------------------
|                                                      |
|                Welcome to SubWarden!                 |
|     A powerful tool by basedygt for detecting        |
|            subdomain takeover risks in Python        |
|                                                      |
--------------------------------------------------------

Usage: python3 subwarden.py <subdomains_file> <output_file> <threads>

Examples:
  python3 subwarden.py subs.txt output.txt
  python3 subwarden.py subs.txt output.txt 20
```
