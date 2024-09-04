from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    queries = relationship("Query", back_populates="user")

class Query(Base):
    __tablename__ = "queries"
    query_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    query_text = Column(String)
    query_type = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    session_id = Column(UUID(as_uuid=True), default=uuid.uuid4)
    device_type = Column(String)
    location = Column(String, nullable=True)
    intent_detected = Column(String)

    user = relationship("User", back_populates="queries")
