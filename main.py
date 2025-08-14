from fastapi import FastAPI, APIRouter
from src.app import endpoints
from src.app.security import jwks
from contextlib import asynccontextmanager
from src.db.db_config import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(lifespan=lifespan)

api = APIRouter()
api.include_router(endpoints.router)
api.include_router(jwks.router)

app.include_router(api)
