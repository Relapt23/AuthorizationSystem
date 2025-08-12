import pytest_asyncio
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from src.db.models import Base, UserInfo
from main import app as fastapi_app
from src.db.db_config import make_session
from httpx import AsyncClient, ASGITransport
from src.app.security import pwd_context
from sqlalchemy.pool import StaticPool


@pytest_asyncio.fixture()
async def test_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture()
async def test_session(test_engine):
    async with test_engine.connect() as conn:
        trans = await conn.begin()
        test_sess = async_sessionmaker(bind=conn, expire_on_commit=False)

        async def override_session() -> AsyncSession:
            async with test_sess() as s:
                yield s

        fastapi_app.dependency_overrides[make_session] = override_session
        try:
            async with test_sess() as session:
                yield session
        finally:
            await trans.rollback()
            fastapi_app.dependency_overrides.pop(make_session, None)


@pytest_asyncio.fixture()
async def client(test_session):
    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_register_success(client, test_session):
    # given
    user = {"login": "test@example.com", "password": "1234"}

    # when
    response = await client.post("/register", json=user)
    data = response.json()

    db_user = (
        await test_session.execute(
            select(UserInfo).where(UserInfo.login == user["login"])
        )
    ).scalar_one_or_none()

    # then
    assert response.status_code == 201
    assert data == {"message": "Success!"}
    assert db_user is not None
    assert db_user.login == user["login"]
    assert pwd_context.verify(user["password"], db_user.password)


@pytest.mark.asyncio
async def test_register_duplicate(client):
    # given
    user = {"login": "test@example.com", "password": "1234"}

    # when
    response = await client.post("/register", json=user)
    duplicate_response = await client.post("/register", json=user)

    # then
    assert response.status_code == 201
    assert duplicate_response.status_code == 400
    assert duplicate_response.json()["detail"] == "user_is_already_registered"


@pytest.mark.asyncio
async def test_login_success(client, test_session, monkeypatch):
    # given
    user = {"login": "test@example.com", "password": "1234"}
    test_session.add(
        UserInfo(login=user["login"], password=pwd_context.hash(user["password"]))
    )
    await test_session.commit()

    def fake_make_jwt_token(username: str) -> str:
        assert username == user["login"]
        return "fake.jwt.token"

    monkeypatch.setattr("src.app.endpoints.make_jwt_token", fake_make_jwt_token)

    # when
    response = await client.post("/login", json=user)
    data = response.json()

    db_user = await test_session.scalar(
        select(UserInfo).where(UserInfo.login == user["login"])
    )

    # then
    assert response.status_code == 200
    assert data["access_token"] == "fake.jwt.token"
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 15 * 60
    assert db_user is not None


@pytest.mark.asyncio
async def test_login_user_not_found(client):
    # given
    user = {"login": "nouser@example.com", "password": "incorrect"}

    # when
    response = await client.post("/login", json=user)
    data = response.json()

    # then
    assert response.status_code == 401
    assert data["detail"] == "incorrect_name_or_password"


@pytest.mark.asyncio
async def test_login_incorrect_password(client, test_session):
    # given
    user = {"login": "test@example.com", "password": "incorrect"}
    test_session.add(
        UserInfo(login="test@example.com", password=pwd_context.hash("correct"))
    )
    await test_session.commit()

    # when
    response = await client.post("/login", json=user)
    data = response.json()

    # then
    assert response.status_code == 401  # (или 401, если так решишь)
    assert data["detail"] == "incorrect_name_or_password"
