from pydantic import BaseModel, EmailStr


class UserResponse(BaseModel):
    login: EmailStr
    password: str


class UserRequest(BaseModel):
    message: str


class TokenSent(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
