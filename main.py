from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from database import SessionLocal, init_db, database
from models import Query, User
from passlib.context import CryptContext
from uuid import UUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.future import select
from pydantic import BaseModel, EmailStr
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))  # Default to 15 minutes if not provided

app = FastAPI()

# Add CORS middleware to allow requests from the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Adjust this to your frontend's URL
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


class QueryCreate(BaseModel):
    user_id: UUID  # Required
    query_text: str  # Required
    session_id: UUID  # Required
    query_type: Optional[str] = None  # Optional
    device_type: Optional[str] = None  # Optional
    location: Optional[str] = None  # Optional
    intent_detected: Optional[str] = None  # Optional


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: UUID
    name: str
    email: EmailStr

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


@app.post("/users/", response_model=UserResponse)
async def create_user(user: UserCreate, session: AsyncSession = Depends(get_session)):
    # Hash the user's password
    hashed_password = get_password_hash(user.password)

    new_user = User(
        name=user.name,
        email=user.email,
        hashed_password=hashed_password
    )

    session.add(new_user)
    try:
        await session.commit()
        await session.refresh(new_user)
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status_code=400, detail="Email already registered")

    return new_user


async def get_current_user(token: str = Depends(oauth2_scheme), session: AsyncSession = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await session.execute(select(User).filter(User.email == username))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    return user


@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).filter(User.email == form_data.username))
    user = result.scalars().first()
    if not user:
        # Return 404 if the user doesn't exist
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/queries/{user_id}")
async def get_user_queries(user_id: UUID, session: AsyncSession = Depends(get_session), current_user: User = Depends(get_current_user)):
    result = await session.execute(select(Query).filter(Query.user_id == user_id))
    queries = result.scalars().all()
    return queries


@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/queries/")
async def create_query(
    query: QueryCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    query_data = query.dict()
    query_data['timestamp'] = datetime.utcnow()
    query_data['user_id'] = current_user.id

    db_query = Query(**query_data)

    session.add(db_query)
    await session.commit()
    await session.refresh(db_query)

    return db_query


@app.get("/conversations/{session_id}")
async def get_conversation_by_session(session_id: UUID, session: AsyncSession = Depends(get_session), current_user: User = Depends(get_current_user)):
    result = await session.execute(select(Query).filter(Query.session_id == session_id))
    conversation = result.scalars().all()
    return conversation


@app.delete("/conversations/{session_id}")
async def delete_conversation(session_id: UUID, session: AsyncSession = Depends(get_session), current_user: User = Depends(get_current_user)):
    result = await session.execute(select(Query).filter(Query.session_id == session_id))
    conversation = result.scalars().all()

    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")

    for query in conversation:
        await session.delete(query)

    await session.commit()
    return {"message": "Conversation deleted successfully"}


@app.on_event("startup")
async def startup():
    await database.connect()
    await init_db()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
