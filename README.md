### Checklist

- [x] Active detection via web content and `cname` records
- [ ] Passive detection via `nxdomain` fingerprints
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

Usage: python3 subwarden.py <subdomains_file> <output_file>
Example:
        python3 subwarden.py subs.txt output.txt
```
