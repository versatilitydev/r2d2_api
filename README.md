# R2D2 API

R2D2 API is a Python-based project that provides a set of functions to interact with various vulnerability databases and scoring systems. It allows users to fetch information about Common Vulnerabilities and Exposures (CVEs), query the National Vulnerability Database (NVD), and retrieve Exploit Prediction Scoring System (EPSS) data.

## Features

- Fetch CVE information from the National Vulnerability Database (NVD)
- Retrieve CVE details based on Common Platform Enumeration (CPE)
- Get Exploit Prediction Scoring System (EPSS) data for CVEs

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/versatilitydev/r2d2_api.git
   cd r2d2_api
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Fetching CVE Information

To fetch information about a specific CVE:

```python
from r2d2_api import get_cve_info

cve_id = "CVE-2021-34527"
cve_data = get_cve_info(cve_id)
if cve_data:
    print(f"CVE Information for {cve_id}:", cve_data)
else:
    print(f"No information found for {cve_id}")
```

### Retrieving CVE Details by CPE

To fetch CVE details based on a Common Platform Enumeration (CPE):

```python
from r2d2_api import fetch_cve_details

cpe = "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
cve_details = fetch_cve_details(cpe)
if cve_details:
    print(f"CVE Details for {cpe}:", cve_details)
else:
    print(f"No CVE details found for {cpe}")
```

### Getting EPSS Data

To retrieve Exploit Prediction Scoring System (EPSS) data for a CVE:

```python
from r2d2_api import fetch_epss_data

cve_id = "CVE-2021-34527"
epss_data = fetch_epss_data(cve_id)
if epss_data:
    print(f"EPSS Data for {cve_id}:", epss_data)
else:
    print(f"No EPSS data found for {cve_id}")
```

## API Keys

Some functions require API keys to access certain services. Make sure to replace the placeholder API keys in the code with your own:

- NVD API Key: Replace `'YOUR_API_KEY_HERE'` with your actual NVD API key.
- FIRST.org API Key (if required): Uncomment and replace `'YOUR_API_KEY_HERE'` with your actual FIRST.org API key.

## Rate Limiting

The API functions implement rate limiting to comply with the usage policies of the respective services:

- NVD API: 50 calls per 30 seconds
- FIRST.org API: 100 calls per 60 seconds (adjust as needed based on actual API requirements)

## Error Handling

All functions include error handling and logging. Make sure to configure the logging level as needed in your application.

## Contributing

Contributions to the R2D2 API project are welcome! Please feel free to submit pull requests or open issues for any bugs or feature requests.

## License

[MIT]

## Contact

For any questions or concerns, please open an issue in the GitHub repository or contact the maintainers directly.
