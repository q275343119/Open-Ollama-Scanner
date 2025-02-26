# -*- coding: utf-8 -*-
# @Date     : 2025/2/26 10:57
# @Author   : q275343119
# @File     : database.py
# @Description:
# -*- coding: utf-8 -*-
# @Date     : 2025/2/13 14:07
# @Author   : q275343119
# @File     : database.py
# @Description:
from collections.abc import AsyncGenerator
from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Text, SMALLINT
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import declarative_base

from config import settings

DATABASE_URL = settings["DATABASE_URL"]

Base = declarative_base()

engine = create_async_engine(
    DATABASE_URL,
    future=True,
    echo=False,
)

# expire_on_commit=False will prevent attributes from being expired
# after commit.
AsyncSessionFactory = async_sessionmaker(
    engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


class FreeOllama(Base):
    __tablename__ = "free_ollama"

    id = Column(Integer, primary_key=True, index=True, comment="主键")
    ip = Column(String, unique=True, index=True, comment="ip")
    models = Column(Text, nullable=True, comment="models")
    active = Column(SMALLINT, default=1, comment="是否存活")
    created_at = Column(DateTime, default=datetime.utcnow, comment="创建时间")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, comment="更新时间")


# Dependency
async def get_db() -> AsyncGenerator:
    async with AsyncSessionFactory() as session:
        try:
            yield session
        except Exception as e:
            print(e)
            raise
