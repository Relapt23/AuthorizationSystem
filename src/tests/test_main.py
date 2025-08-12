import pytest_asyncio
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from src.db.models import Base, UserInfo
from main import app as fastapi_app
from src.db.db_config import make_session
from httpx import AsyncClient, ASGITransport
from src.app.security.jwt_maker import pwd_context
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
    register_params = {"login": "test@example.com", "password": "1234"}

    # when
    response = await client.post("/register", json=register_params)
    data = response.json()

    db_user = (
        await test_session.execute(
            select(UserInfo).where(UserInfo.login == register_params["login"])
        )
    ).scalar_one_or_none()

    # then
    assert response.status_code == 201
    assert data == {"message": "Success!"}
    assert db_user is not None
    assert db_user.login == register_params["login"]
    assert pwd_context.verify(register_params["password"], db_user.password)


@pytest.mark.asyncio
async def test_register_duplicate(client):
    # given
    register_params = {"login": "test@example.com", "password": "1234"}

    # when
    response = await client.post("/register", json=register_params)
    duplicate_response = await client.post("/register", json=register_params)

    # then
    assert response.status_code == 201
    assert duplicate_response.status_code == 400
    assert duplicate_response.json()["detail"] == "user_is_already_registered"


@pytest.mark.asyncio
async def test_login_success(client, test_session, monkeypatch):
    # given
    register_params = {"login": "test@example.com", "password": "1234"}
    test_session.add(
        UserInfo(
            login=register_params["login"],
            password=pwd_context.hash(register_params["password"]),
        )
    )
    await test_session.commit()

    def fake_make_jwt_token(username: str) -> str:
        assert username == register_params["login"]
        return "fake.jwt.token"

    monkeypatch.setattr("src.app.endpoints.make_jwt_token", fake_make_jwt_token)

    # when
    response = await client.post("/login", json=register_params)
    data = response.json()

    db_user = await test_session.scalar(
        select(UserInfo).where(UserInfo.login == register_params["login"])
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
    register_params = {"login": "nouser@example.com", "password": "incorrect"}

    # when
    response = await client.post("/login", json=register_params)
    data = response.json()

    # then
    assert response.status_code == 401
    assert data["detail"] == "incorrect_name_or_password"


@pytest.mark.asyncio
async def test_login_incorrect_password(client, test_session):
    # given
    register_params = {"login": "test@example.com", "password": "incorrect"}
    test_session.add(
        UserInfo(login="test@example.com", password=pwd_context.hash("correct"))
    )
    await test_session.commit()

    # when
    response = await client.post("/login", json=register_params)
    data = response.json()

    # then
    assert response.status_code == 401
    assert data["detail"] == "incorrect_name_or_password"
