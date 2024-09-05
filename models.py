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
    
    # Relationship with the Query model
    queries = relationship("Query", back_populates="user")

class Query(Base):
    __tablename__ = "queries"
    query_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # ForeignKey linking to the User model
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    
    query_text = Column(String, nullable=False)
    query_type = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    session_id = Column(UUID(as_uuid=True), nullable=False, default=uuid.uuid4)
    device_type = Column(String, nullable=True)
    location = Column(String, nullable=True)
    intent_detected = Column(String, nullable=True)

    # Relationship with the User model
    user = relationship("User", back_populates="queries")
