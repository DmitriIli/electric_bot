
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Depends, FastAPI, HTTPException, status, Form, Cookie, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse, JSONResponse
from passlib.context import CryptContext


import config
from model import User, UserInDB, Token, TokenData, TestUser, Feedback, UserCreate
from db import user_db, product_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

app = FastAPI()


async def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


async def authenticate_user(user_db,  username: str,  password: str):
    user = await get_user(user_db, username)
    if not user:
        return False
    if not await verify_password(password, user.hashed_password):
        return False
    return user


async def create_access_token(data: dict,  expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(
        to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.SECRET_KEY,
                             algorithms=[config.ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user_in_db = await get_user(user_db, username=token_data.username)
    if user_in_db is None:
        raise credentials_exception
    return user_in_db


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
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = await authenticate_user(user_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(
        minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get('/user/me')
async def read_user_me(current_user: Annotated[User, Depends(get_current_active_user)],) -> User:
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]


@app.get("/")
async def get_index():
    return FileResponse('index.html')


@app.post("/calculate")
async def calculate(par1: int, par2: int):
    return {'resault': {par1+par2}}


@app.get('/test')
async def test_user(user_name, id) -> JSONResponse:
    user = TestUser(user_name=user_name, id=id)
    return user.model_dump()


@app.get('/feedback')
async def feedback(feedback: Feedback):
    return {"message": "Feedback received. Thank you, {feedback.name}!"}


@app.get('/create_user')
async def create_user(name: str, email: str, age: int, is_subscribed: bool = False) -> UserCreate:
    user = UserCreate(name=name, email=email, age=age,
                      is_subscribed=is_subscribed)
    return user.model_dump()


@app.get('/product/{product_id}')
async def get_product(product_id: int):
    try:
        product = [product_db[key] for key in product_db.keys(
        ) if product_db[key]['product_id'] == product_id][0]
        return product
    except Exception as e:
        return e


@app.get('/product/search/')
async def serch_product(keyword: str, category: str | None = None, limit: int = 10):
    try:
        if category:
            products_category = [product_db[key] for key in product_db.keys(
            ) if product_db[key]['category'] == category]
            products = [
                product for product in products_category if product['name'].lower().find(keyword.lower()) != -1][:limit]
            return products
        pruducts = [product_db[key] for key in product_db.keys(
        ) if product_db[key]['name'].lower().find(keyword.lower()) != -1]
        return pruducts
    except Exception as e:
        return e


@app.post('/login')
async def login_user(response: Response, username: str = Form(...), password: str = Form(...)) -> Response:
    try:
        user = user_db[username]
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username",
        )
    if await verify_password(password, user['hashed_password']):
        token = 'username' + ' ' + 'session_token'
        user['session_token'] = token
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )
    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(key='session_token', value=token, httponly=True)

    return response


@app.get("/user")
async def get_user(request: Request):
    session_token = request.cookies.get('session_token')
    print(session_token)
    if session_token is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if session_token != "jonhdoe session_token":
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {"username": "user123", "email": "user123@example.com"}
