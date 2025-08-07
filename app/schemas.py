from pydantic import BaseModel, EmailStr


class Register(BaseModel):
    login: EmailStr
    password: str

class Login(BaseModel):
    login: EmailStr
    password: str