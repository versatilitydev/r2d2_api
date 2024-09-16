import requests
from functools import wraps
from ratelimit import limits, sleep_and_retry
import logging
from typing import Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@sleep_and_retry
@limits(calls=100, period=60)  # Adjust rate limits as per FIRST.org API requirements
def fetch_epss_data(cve_id: str) -> Optional[Dict]:
    """
    Fetch EPSS (Exploit Prediction Scoring System) data for a given CVE ID.

    This function is rate-limited to 100 calls per 60 seconds to comply with potential API usage policies.
    Adjust the rate limits based on the actual requirements of the FIRST.org API.

    Args:
        cve_id (str): The CVE identifier to look up EPSS data for (e.g., "CVE-2021-34527").

    Returns:
        Optional[Dict]: A dictionary containing the EPSS data if found and request was successful, None otherwise.

    Raises:
        requests.RequestException: If an error occurs during the API request.
    """
    BASE_URL = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    try:
        response = requests.get(BASE_URL)  
        response.raise_for_status() 
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error occurred while fetching EPSS data for {cve_id}: {str(e)}")
        return None