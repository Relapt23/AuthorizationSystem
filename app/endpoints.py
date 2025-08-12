from fastapi import APIRouter, Depends, HTTPException

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models import UserInfo
from app.schemas import UserResponse, UserRequest, LoginResponse
from db.db_config import make_session
from app.security import pwd_context, make_jwt_token

router = APIRouter()


@router.post("/register")
async def register(
    user: UserRequest, session: AsyncSession = Depends(make_session)
) -> UserResponse:
    user_in_db = (
        await session.execute(select(UserInfo).where(UserInfo.login == user.login))
    ).scalar_one_or_none()

    if user_in_db:
        raise HTTPException(detail="user_is_already_registered", status_code=400)

    new_user = UserInfo(login=user.login, password=pwd_context.hash(user.password))
    session.add(new_user)
    await session.commit()

    return UserResponse(message="Success!")


@router.post("/login")
async def login(
    user: UserRequest, session: AsyncSession = Depends(make_session)
) -> LoginResponse:
    user_in_db = (
        await session.execute(select(UserInfo).where(UserInfo.login == user.login))
    ).scalar_one_or_none()

    if not user_in_db or not pwd_context.verify(user.password, user_in_db.password):
        raise HTTPException(detail="incorrect_name_or_password", status_code=404)

    token = make_jwt_token(user.login)

    return LoginResponse(access_token=token, token_type="bearer", expires_in=15 * 60)
