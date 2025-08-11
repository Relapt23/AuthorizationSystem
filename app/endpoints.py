from fastapi import APIRouter, Depends

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import UserInfo
from app.schemas import UserResponse, CustomException
from db.db_config import make_session
from app.security import pwd_context, make_jwt_token

router = APIRouter()


@router.post("/register")
async def register(
    user: UserResponse, session: AsyncSession = Depends(make_session)
) -> dict:
    user_in_db = (
        await session.execute(select(UserInfo).where(UserInfo.login == user.login))
    ).scalar_one_or_none()
    if user_in_db:
        raise CustomException(detail="user_is_already_registered", status_code=400)
    hashed_password = pwd_context.hash(user.password)
    new_user = UserInfo(login=user.login, password=hashed_password)
    session.add(new_user)
    await session.commit()
    return {"message": "Success!"}


@router.post("/login")
async def login(
    user: UserResponse, session: AsyncSession = Depends(make_session)
) -> dict:
    user_in_db = (
        await session.execute(select(UserInfo).where(UserInfo.login == user.login))
    ).scalar_one_or_none()
    if not user_in_db:
        raise CustomException(detail="user_not_found", status_code=404)
    if not pwd_context.verify(user.password, user_in_db.password):
        raise CustomException(detail="incorrect_name_or_password", status_code=400)
    token = make_jwt_token(user.login)
    return {"access_token": token, "token_type": "bearer", "expires_in": 15 * 60}
