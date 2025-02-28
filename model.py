from pydantic import BaseModel, computed_field
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
    age: int

    @computed_field
    @property
    def is_adult(self) -> bool:
        return self.age >= 18


class UserInDB(User):
    hashed_password: str


class Hero(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    age: int | None = Field(default=None, index=True)


class TestUser(BaseModel):
    user_name: str
    id: int


class Feedback(BaseModel):
    name: str
    message: str
