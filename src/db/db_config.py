from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from src.db.models import Base
import os


class DBConfig:
    HOST: str = os.getenv("DB_HOST")
    PORT: str = os.getenv("DB_PORT")
    USER: str = os.getenv("POSTGRES_USER")
    PASSWORD: str = os.getenv("POSTGRES_PASSWORD")
    DATABASE: str = os.getenv("POSTGRES_DB")


async def make_engine():
    return create_async_engine(
        f"postgresql+asyncpg://{DBConfig.USER}:{DBConfig.PASSWORD}@{DBConfig.HOST}:{DBConfig.PORT}/{DBConfig.DATABASE}",
        echo=True,
    )


async def make_session():
    engine = await make_engine()
    sess = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with sess() as session:
        yield session


async def init_db():
    engine = await make_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
