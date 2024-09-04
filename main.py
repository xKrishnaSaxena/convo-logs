from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from database import SessionLocal, init_db, database
from models import Query
from models import User
from passlib.context import CryptContext
from uuid import UUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.future import select
from pydantic import BaseModel,EmailStr
from datetime import datetime

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Dependency to get the session
async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session

class QueryCreate(BaseModel):
    user_id: UUID
    query_text: str
    query_type: str
    session_id: UUID
    device_type: str
    location: str = None
    intent_detected: str

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


@app.on_event("startup")
async def startup():
    await database.connect()
    await init_db()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.post("/queries/")
async def create_query(query: QueryCreate, session: AsyncSession = Depends(get_session)):
    db_query = Query(**query.dict(), timestamp=datetime.utcnow())
    session.add(db_query)
    await session.commit()
    await session.refresh(db_query)
    return db_query

@app.post("/users/", response_model=UserResponse)  # Use the new UserResponse model
async def create_user(user: UserCreate, session: AsyncSession = Depends(get_session)):
    # Hash the user's password
    hashed_password = pwd_context.hash(user.password)
    
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