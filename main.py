
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel

import config


user_db = {
    'jonhdoe': {
        'username': 'jonhdoe',
        'full_name': 'Jonh Doe',
        'email': 'jonhdoe@mail.mail',
        'hashed_password': 'password'.__hash__(),
        'disable': False
    },
    'alice': {
        'username': 'alice',
        'full_name': 'Alice Doe',
        'email': 'alicedoe@mail.mail',
        'hashed_password': 'password',
        'disable': True
    },
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

app = FastAPI()


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


async def hash_password(password):
    return pwd_context.hash(password)


async def get_hash(password: str):
    return password.__hash__()


async def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


async def decode_token(token):
    user = await get_user(user_db, token)
    return user


async def get_hash_password(password: str):
    return password


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = await decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='invaalid authentication',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disable:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Inactive user',
        )
    return current_user


@app.post('/token')
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = user_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='incorrect user name',
        )
    user = UserInDB(**user_dict)
    print(user)
    hashed_password = await get_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='incorrect user password',
        )
    return {'access_token': user.username, 'token_type': 'bearer'}


@app.get('/user/me')
async def read_user_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user
