from pydantic import BaseModel, Field
from typing import List, Optional

class RuleHit(BaseModel):
    id: str
    severity: int
    message: staticmethod
    
class ScanRequest(BaseModel):
    from_addr : str = ""
    subject : str = ""
    body : str = Field(..., min_length= 1)
    
class ScanResponse(BaseModel):
    classification : str
    confidence : float
    ml_probability : float
    rules_score : int 
    rule_hits : List[RuleHit]
    extracted_links : List[str]
    
    