import httpx

def get_header(url):
    malicious = False
    bad_headers = [ "gophish", "Apache" ]

    try:
        with httpx.Client() as client:
            resp = client.get('https://' + url, verify=False, allow_redirects=False)
            malicious = any('header' in str(resp.headers) for header in bad_headers)
            return resp.headers['server'], malicious
    except:
        return "unknown", 0
