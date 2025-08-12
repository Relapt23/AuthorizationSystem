from pydantic import BaseModel, EmailStr


class UserRequest(BaseModel):
    login: EmailStr
    password: str


class UserResponse(BaseModel):
    message: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
