from pydantic import BaseModel, EmailStr


class RegisterParams(BaseModel):
    login: EmailStr
    password: str


class RegisterResponse(BaseModel):
    message: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
