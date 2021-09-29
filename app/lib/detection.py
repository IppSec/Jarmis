import httpx
import base64
import json

from io import BytesIO
from urllib.parse import urlparse

from app.external.CobaltStrikeParser.parse_beacon_config import cobaltstrikeConfig

def cobaltstrike(url):
    """
    Attempt to grab the C2 Config from Cobalt Strike Servers.
    """
    url = urlparse(url)
    # Default Stager Checksums
    paths = [ "/ab2h", "/iLs2" ]
    if url.path != '/':
        paths.append(url.path)
    with httpx.Client(verify=False) as client:
        for path in paths:
            r = client.get("https://" + url.netloc + path, allow_redirects=False)
            if r.status_code == 200:
                config = cobaltstrikeConfig(BytesIO(r.content)).parse_config(version=3, as_json=True)
                if config: return config
                config = cobaltstrikeConfig(BytesIO(r.content)).parse_config(version=4, as_json=True)
                if config: return config
                config = cobaltstrikeConfig(BytesIO(r.content)).parse_encrypted_config(version=3, as_json=True)
                if config: return config
                config = cobaltstrikeConfig(BytesIO(r.content)).parse_encrypted_config(version=4, as_json=True)
                if config: return config
    return False




def inspect(url, c2=None):
    malicious = False
    bad_headers = [ "gophish", "Apache" ]
    meta = {}
    if c2 == 'CobaltStrike':
        cs_config = cobaltstrike(url)
        # ToDo. This is encoded weird and breaks pydantic.  Need a better fix
        if cs_config:
            malicious = True
            cs_config['ProcInject_PrependAppend_x86'] = 'null'
            cs_config['ProcInject_PrependAppend_x64'] = 'null'
            for item in cs_config.keys():
                if isinstance(cs_config[item], (bytes, bytearray)):
                    cs_config[item] = base64.b64encode(cs_config[item])
            meta['config'] = cs_config

    try:
        with httpx.Client(verify=False) as client:
            resp = client.get(url, allow_redirects=False)
            header = any('header' in str(resp.headers) for header in bad_headers)
            if header:
                malicious = header
            meta['headers'] = resp.headers
            return meta, malicious
    except Exception as e:
        return meta, malicious
