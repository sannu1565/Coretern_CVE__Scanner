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

## Setup

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/cve-scanner.git
cd cve-scanner

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Set your NVD API key for higher rate limits
#    Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-key-here"
```

## Usage

### Interactive mode (single scan)

```bash
python main.py
```

```
=== CVE Scanner ===
Enter software/product name: Apache HTTP Server
Enter version number: 2.4.49

🔍 Scanning: Apache HTTP Server 2.4.49
────────────────────────────────────────────────────────────
  Apache HTTP Server 2.4.49
────────────────────────────────────────────────────────────

  [CRITICAL]   CVE-2021-41773
  ↳ A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49…
```

### Batch mode (from file)

```bash
python main.py --batch                        # uses data/software_list.txt
python main.py --batch path/to/my_list.txt   # custom file
```

`data/software_list.txt` format:

```
# Lines starting with # are ignored
Apache HTTP Server,2.4.49
OpenSSL,1.1.1k
Log4j,2.14.1
```

Results are written to `data/results.json` after the batch run.

## API rate limits

| Auth | Limit |
|------|-------|
| No API key | 5 requests / 30 seconds |
| With API key | 50 requests / 30 seconds |

The scanner sleeps 1.5 s between requests by default. Adjust `RATE_LIMIT_SLEEP` in `main.py` if you have an API key.

## License

MIT
