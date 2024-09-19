---
title: testdoc
---
# Introduction

This document will walk you through the implementation of the feature that fetches CVE (Common Vulnerabilities and Exposures) and EPSS (Exploit Prediction Scoring System) data.

The feature includes:

1. Fetching CVE details for a given CPE.
2. Fetching CVE information for a specific CVE ID.
3. Fetching EPSS data for a specific CVE ID.
4. Implementing rate limits to comply with API usage policies.

We will cover:

1. Why rate limits are implemented.
2. How logging is configured.
3. How API requests are structured and handled.
4. Error handling in API requests.

# Fetching CVE details for a given CPE

<SwmSnippet path="/cpe_cve_fetch.py" line="5">

---

We start by defining the function <SwmToken path="/cpe_cve_fetch.py" pos="12:2:2" line-data="def fetch_cve_details(cpe: str) -&gt; Optional[Dict]:">`fetch_cve_details`</SwmToken> in <SwmPath>[cpe_cve_fetch.py](/cpe_cve_fetch.py)</SwmPath>. This function is <SwmToken path="/cpe_cve_fetch.py" pos="16:7:9" line-data="    This function is rate-limited to 50 calls per 30 seconds to comply with the NVD API usage policy.">`rate-limited`</SwmToken> to 50 calls per 30 seconds to comply with the NVD API usage policy.

```

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@sleep_and_retry
@limits(calls=50, period=30)
def fetch_cve_details(cpe: str) -> Optional[Dict]:
    """
    Fetch CVE (Common Vulnerabilities and Exposures) details for a given CPE (Common Platform Enumeration).
```

---

</SwmSnippet>

<SwmSnippet path="/cpe_cve_fetch.py" line="15">

---

The function takes a CPE string as an argument and returns a dictionary containing CVE details if found.

```

    This function is rate-limited to 50 calls per 30 seconds to comply with the NVD API usage policy.

    Args:
        cpe (str): The CPE string to look up vulnerabilities for.

    Returns:
        Optional[Dict]: A dictionary containing the CVE details if found and request was successful, None otherwise.
```

---

</SwmSnippet>

<SwmSnippet path="/cpe_cve_fetch.py" line="23">

---

We set up the API request with the necessary headers and base URL. The API key is required for authentication.

```

    Raises:
        requests.RequestException: If an error occurs during the API request.
    """
    API_KEY = "YOUR_API_KEY_HERE"
    BASE_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
    HEADERS = {
        'Content-Type': 'application/json',
        'apikey': API_KEY
    }
```

---

</SwmSnippet>

<SwmSnippet path="/cpe_cve_fetch.py" line="33">

---

The function makes the API request and handles any potential errors. If the request is successful, it returns the JSON response. Otherwise, it logs the error and returns `None`.

```

    try:
        response = requests.get(BASE_URL, headers=HEADERS)
        response.raise_for_status()  # This will raise an HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error occurred while fetching CVE details for {cpe}: {str(e)}")
        return None
```

---

</SwmSnippet>

# Fetching CVE information for a specific CVE ID

<SwmSnippet path="/cve_fetch.py" line="5">

---

Next, we define the function <SwmToken path="/cve_fetch.py" pos="11:2:2" line-data="def get_cve_info(cve_id: str) -&gt; dict | None:">`get_cve_info`</SwmToken> in <SwmPath>[cve_fetch.py](/cve_fetch.py)</SwmPath>. This function is also <SwmToken path="/cpe_cve_fetch.py" pos="16:7:9" line-data="    This function is rate-limited to 50 calls per 30 seconds to comply with the NVD API usage policy.">`rate-limited`</SwmToken> to 50 calls per 30 seconds.

```
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@sleep_and_retry
@limits(calls=50, period=30)
def get_cve_info(cve_id: str) -> dict | None:
    """
    Retrieve information about a specific CVE (Common Vulnerabilities and Exposures) from the NVD (National Vulnerability Database).
```

---

</SwmSnippet>

<SwmSnippet path="/cve_fetch.py" line="14">

---

The function takes a CVE ID as an argument and returns a dictionary containing the CVE information if found.

```

    This function is rate-limited to 50 calls per 30 seconds to comply with the NVD API usage policy.

    Args:
        cve_id (str): The CVE identifier to look up (e.g., "CVE-2021-34527").

    Returns:
        dict | None: A dictionary containing the CVE information if found, None otherwise.
```

---

</SwmSnippet>

<SwmSnippet path="/cve_fetch.py" line="22">

---

Similar to the previous function, we set up the API request with the necessary headers and base URL.

```

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
```

---

</SwmSnippet>

<SwmSnippet path="/cve_fetch.py" line="22">

---

The function makes the API request, processes the response, and handles errors. If no data is found, it logs a warning.

```

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
```

---

</SwmSnippet>

# Fetching EPSS data for a specific CVE ID

<SwmSnippet path="/epss_fetch.py" line="7">

---

Finally, we define the function <SwmToken path="/epss_fetch.py" pos="13:2:2" line-data="def fetch_epss_data(cve_id: str) -&gt; Optional[Dict]:">`fetch_epss_data`</SwmToken> in <SwmPath>[epss_fetch.py](/epss_fetch.py)</SwmPath>. This function is <SwmToken path="/cpe_cve_fetch.py" pos="16:7:9" line-data="    This function is rate-limited to 50 calls per 30 seconds to comply with the NVD API usage policy.">`rate-limited`</SwmToken> to 100 calls per 60 seconds to comply with the [FIRST.org](http://FIRST.org) API requirements.

```
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@sleep_and_retry
@limits(calls=100, period=60)  # Adjust rate limits as per FIRST.org API requirements
def fetch_epss_data(cve_id: str) -> Optional[Dict]:
    """
    Fetch EPSS (Exploit Prediction Scoring System) data for a given CVE ID.
```

---

</SwmSnippet>

<SwmSnippet path="/epss_fetch.py" line="16">

---

The function takes a CVE ID as an argument and returns a dictionary containing the EPSS data if found.

```

    This function is rate-limited to 100 calls per 60 seconds to comply with potential API usage policies.
    Adjust the rate limits based on the actual requirements of the FIRST.org API.

    Args:
        cve_id (str): The CVE identifier to look up EPSS data for (e.g., "CVE-2021-34527").

    Returns:
        Optional[Dict]: A dictionary containing the EPSS data if found and request was successful, None otherwise.
```

---

</SwmSnippet>

<SwmSnippet path="/epss_fetch.py" line="25">

---

We set up the API request with the base URL and handle any potential errors. If the request is successful, it returns the JSON response. Otherwise, it logs the error and returns `None`.

```

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
```

---

</SwmSnippet>

# Conclusion

This feature ensures that we can fetch CVE and EPSS data while adhering to API usage policies. The implementation includes rate limits, logging, and error handling to ensure reliable and compliant API interactions.

<SwmMeta version="3.0.0" repo-id="Z2l0aHViJTNBJTNBcjJkMl9hcGklM0ElM0F2ZXJzYXRpbGl0eWRldg==" repo-name="r2d2_api"><sup>Powered by [Swimm](https://app.swimm.io/)</sup></SwmMeta>
