from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: str
    is_active: bool

    model_config = {"from_attributes": True}


class RoleUpdate(BaseModel):
    role: str = Field(pattern="^(user|admin)$")


class Message(BaseModel):
    detail: str
