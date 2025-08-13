from fastapi import APIRouter, Depends, HTTPException, status

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.db.models import UserInfo
from src.app.schemas import RegisterResponse, LoginResponse, RegisterParams
from src.db.db_config import make_session
from src.app.security.jwt_maker import pwd_context, make_jwt_token

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    register_params: RegisterParams, session: AsyncSession = Depends(make_session)
) -> RegisterResponse:
    user_in_db = (
        await session.execute(
            select(UserInfo).where(UserInfo.email == register_params.email)
        )
    ).scalar_one_or_none()

    if user_in_db:
        raise HTTPException(detail="user_is_already_registered", status_code=400)

    new_user = UserInfo(
        email=register_params.email, password=pwd_context.hash(register_params.password)
    )
    session.add(new_user)
    await session.commit()

    return RegisterResponse(message="Success!")


@router.post("/login")
async def login(
    login_params: RegisterParams, session: AsyncSession = Depends(make_session)
) -> LoginResponse:
    user_in_db = (
        await session.execute(
            select(UserInfo).where(UserInfo.email == login_params.email)
        )
    ).scalar_one_or_none()

    if not user_in_db or not pwd_context.verify(
        login_params.password, user_in_db.password
    ):
        raise HTTPException(detail="incorrect_name_or_password", status_code=401)

    token = make_jwt_token(login_params.email)

    return LoginResponse(access_token=token, token_type="bearer", expires_in=15 * 60)
