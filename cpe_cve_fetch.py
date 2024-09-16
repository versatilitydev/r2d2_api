import requests
from ratelimit import limits, sleep_and_retry
import logging
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@sleep_and_retry
@limits(calls=50, period=30)
def fetch_cve_details(cpe: str) -> Optional[Dict]:
    """
    Fetch CVE (Common Vulnerabilities and Exposures) details for a given CPE (Common Platform Enumeration).

    This function is rate-limited to 50 calls per 30 seconds to comply with the NVD API usage policy.

    Args:
        cpe (str): The CPE string to look up vulnerabilities for.

    Returns:
        Optional[Dict]: A dictionary containing the CVE details if found and request was successful, None otherwise.

    Raises:
        requests.RequestException: If an error occurs during the API request.
    """
    API_KEY = "YOUR_API_KEY_HERE"
    BASE_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
    HEADERS = {
        'Content-Type': 'application/json',
        'apikey': API_KEY
    }

    try:
        response = requests.get(BASE_URL, headers=HEADERS)
        response.raise_for_status()  # This will raise an HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error occurred while fetching CVE details for {cpe}: {str(e)}")
        return None