"""
event_log/database.py
SQLAlchemy setup for SQLite database.
"""
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "security_logs.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Rule(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True, index=True)
    phrase = Column(String, unique=True, index=True)
    category = Column(String)
    weight = Column(Integer, default=2)

class EventLog(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.now)
    api_key = Column(String, index=True) 
    ip_address = Column(String)
    prompt = Column(String)
    risk_score = Column(Integer)
    kw_score = Column(Integer)
    sem_score = Column(Integer)
    risk_mode = Column(String)
    categories = Column(String)
    llm_reasoning = Column(String)
    tokens = Column(Integer, default=0)

Base.metadata.create_all(bind=engine)
