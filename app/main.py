from fastapi import FastAPI, APIRouter, Form
from starlette.middleware.cors import CORSMiddleware

from pydantic import BaseModel
from typing import Optional, Union

from app.schemas import Jarm, Jarm1, Jarm2, JarmSearchResults, FetchJarm1, FetchJarm2

from app.lib.jarm import get_jarm
from app.lib.getheader import get_header
from base64 import b64decode

from urllib.parse import urlparse
import json
import re

description = """
Jarmis helps identify malicious TLS Services by checking JARM Signatures and Metadata.

## What is a jarm?

* 62 Character non-random fingerprint of an SSL Service.
* First 30 characters are Cipher and TLS Versions.
* Last 32 characters are truncated Sha256 Hash of extensions.

## Jarm Collisions

* The first 30 characters, it's the same SSL Configuration.
* The last 32 characters, it's the same server.  
* Full collisions are possible.  That is why this service also utilzies metadata when deconfliction is necessary.

Backend coded by ippsec
"""


# Todo Convert To Database
f = open('data/jarms.json')
JARMS = json.load(f)
f.close()


app = FastAPI(title="Jarmis API", description=description, openapi_url="/openapi.json")

api_router = APIRouter()

@api_router.get("/api/v1/search/id/{jarm_id}", status_code=200, response_model=Union[Jarm2, Jarm1])
def search_id(*, jarm_id: int) -> dict: 
    """
    Search for JARM Signature by internal ID
    """
    result = [jarm for jarm in JARMS if jarm["id"] == jarm_id]
    if result:
        return result[0]

@api_router.get("/api/v1/search/signature/", status_code=200, response_model=JarmSearchResults)
def search_signature(
    keyword: Optional[str] = None, max_results: Optional[int] = 10
) -> dict:
    """
    Search for all signatures with a jarm 
    """
    if not keyword:
        # we use Python list slicing to limit results
        # based on the max_results query parameter
        return {"results": JARMS[:max_results]} 

    results = filter(lambda jarm: keyword.lower() in jarm["sig"].lower(), JARMS) 
    return {"results": list(results)[:max_results]}

@api_router.get("/api/v1/fetch", status_code=200, response_model=Union[FetchJarm2, FetchJarm1])
def fetch_jarm(*, endpoint: str ):
    """
    Query an endpoint to retrieve its JARM and grab metadata if malicious.
    """
    try:
        endpoint = json.loads(request.json())['endpoint']
    except:
        None
    if '//' not in endpoint:
        endpoint = 'https://' + endpoint
    o = urlparse(endpoint)
    resp = {}
    resp = json.loads(get_jarm(o.netloc))
    results = filter(lambda jarm: resp['sig'] == jarm["sig"], JARMS)
    for result in results:
        if result['ismalicious'] == '1':
            try:
                resp['note'] = result['note'] + '?'
                resp['server'], resp['ismalicious'] = get_header(o.netloc + o.path)
                if resp['ismalicious']:
                    resp['note'] = result['note']

            except Exception as e:
                print(str(e))
                resp['server'] = ""
                resp['ismalicious'] = 0
    return resp


app.include_router(api_router)


if __name__ == "__main__":
    # Use this for debugging purposes only
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="debug")
