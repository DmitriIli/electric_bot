from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    fullname: str | None = None
    disable: bool | None = None


class UserInDB(User):
    hashed_password: str


class Hero(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    age: int | None = Field(default=None, index=True)
    
