from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from databases import Database
from models import Base
import urllib.parse
from dotenv import load_dotenv
import os

load_dotenv()

password = urllib.parse.quote_plus(os.getenv("DATABASE_PASSWORD"))
DATABASE_URL = f"postgresql+asyncpg://postgres:{password}@127.0.0.1:5432/convoLogs"

database = Database(DATABASE_URL)
engine = create_async_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=AsyncSession
)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
