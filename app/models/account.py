class Account(BaseModel):
    user_id: str
    balance: float = 0