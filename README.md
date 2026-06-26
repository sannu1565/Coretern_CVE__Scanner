# CVE Vulnerability Scanner

A lightweight Python tool that queries the [NVD (National Vulnerability Database)](https://nvd.nist.gov/) REST API to surface known CVEs for a given software product and version.

## Features

- Interactive single-scan mode
- Batch scan from a CSV file
- CVSS v3.1 and v2 severity detection
- JSON output for downstream processing
- Optional NVD API key support (higher rate limits)

## Project structure

```
cve-scanner/
├── main.py                 # Core scanner — search, parse, output
├── requirements.txt
├── data/
│   ├── software_list.txt   # Batch input: product,version per line
│   └── results.json        # Generated after a batch scan
└── README.md
```