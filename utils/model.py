from sqlalchemy import Column, Text, CHAR, Integer, VARCHAR
from sqlalchemy.ext.declarative import declarative_base

SQLAlchemy = declarative_base()


class User(SQLAlchemy):
    __tablename__ = 'user'

    uid = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(VARCHAR(64), unique=True, index=True)
    public_key = Column(Text)
    key_hash = Column(CHAR(64))
