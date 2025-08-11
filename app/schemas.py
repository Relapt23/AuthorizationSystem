from pydantic import BaseModel, EmailStr
from fastapi import HTTPException


class UserResponse(BaseModel):
    login: EmailStr
    password: str


class CustomException(HTTPException):
    def __init__(self, detail: str, status_code: int):
        super().__init__(status_code=status_code, detail=detail)
