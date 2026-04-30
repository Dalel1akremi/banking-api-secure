from pydantic import BaseModel

class Account(BaseModel):
    user_id: str
    balance: float = 0