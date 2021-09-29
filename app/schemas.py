from pydantic import BaseModel, HttpUrl

from typing import Sequence, Optional, Union

class Jarm(BaseModel):
    id: int
    sig: str
    ismalicious: Optional[bool]
    endpoint: str
    note: Optional[str]
    server: str

class Jarm1(BaseModel):
    id: int
    sig: str
    ismalicious: Optional[bool]
    endpoint: str
    note: Optional[str]

class Jarm2(BaseModel):
    id: int
    sig: str
    ismalicious: Optional[bool]
    endpoint: str
    note: Optional[str]
    server: str

class FetchJarm1(BaseModel):
    sig: str
    endpoint: str
    note: str

class FetchJarm2(BaseModel):
    sig: str
    ismalicious: bool
    endpoint: str
    note: Optional[str]
    server: Optional[str]


class JarmSearchResults(BaseModel):
    results: Sequence[Union[Jarm2,Jarm1]]

class FetchJarm(BaseModel):
    endpoint: str
