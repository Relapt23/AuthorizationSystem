from fastapi import FastAPI
from app import endpoints
from contextlib import asynccontextmanager
from db.db_config import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(lifespan=lifespan)

app.include_router(endpoints.router)
