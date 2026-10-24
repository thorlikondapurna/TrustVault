from pydantic import BaseModel, EmailStr 

class PermissionRequest(BaseModel):
    user_id: int
    permission: str

class RevokePermissionRequest(BaseModel):
    user_id: int

class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str