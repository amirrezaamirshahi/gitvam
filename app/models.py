from pydantic import BaseModel, EmailStr, Field, validator
from typing import Literal, Optional
import re

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=20, pattern=r'^[a-zA-Z0-9_.-]+$', description="Username must be unique and contain only letters, numbers, and certain special characters.")
    first_name: str
    last_name: str
    email: EmailStr
    user_type: Literal['کاربرعادی', 'کاربر صندوق', 'مدیران', 'ادمین']
    category: Literal['مرکز کنترل', 'مهراباد', 'امام خمینی']
    description: Optional[str] = None

    @validator('username')
    def validate_username(cls, v):
        if re.match(r'^[a-zA-Z0-9_.-]+$', v) is None:
            raise ValueError('Username must contain only letters, numbers, and certain special characters.')
        return v

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long and contain at least one uppercase letter.")
    confirm_password: str

    @validator('password')
    def validate_password(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class User(UserBase):
    class Config:
        from_attributes = True
