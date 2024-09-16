import requests
from ratelimit import limits, sleep_and_retry
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@sleep_and_retry
@limits(calls=50, period=30)
def get_cve_info(cve_id: str) -> dict | None:
    """
    Retrieve information about a specific CVE (Common Vulnerabilities and Exposures) from the NVD (National Vulnerability Database).

    This function is rate-limited to 50 calls per 30 seconds to comply with the NVD API usage policy.

    Args:
        cve_id (str): The CVE identifier to look up (e.g., "CVE-2021-34527").

    Returns:
        dict | None: A dictionary containing the CVE information if found, None otherwise.

    Raises:
        requests.RequestException: If an error occurs during the API request.
    """
    API_KEY = "YOUR_API_KEY_HERE"
    BASE_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    HEADERS = {
        'Content-Type': 'application/json',
        'apikey': API_KEY
    }
    
    try:
        response = requests.get(BASE_URL, headers=HEADERS)
        response.raise_for_status()
        data = response.json()
        
        if data['totalResults'] > 0:
            return data['vulnerabilities'][0]['cve']
        else:
            logger.warning(f"No data found for {cve_id}")
            return None
    except requests.RequestException as e:
        logger.error(f"Error occurred while fetching {cve_id}: {str(e)}")
        return None