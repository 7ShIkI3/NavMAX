"""
Moteur SQLAlchemy asynchrone — session factory et création des tables.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from navmax.core.config import config
from navmax.core.logging import get_logger

logger = get_logger(__name__)

engine = create_async_engine(
    config.database_url,
    echo=config.debug,
    future=True,
)

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def create_all() -> None:
    """Crée toutes les tables en base."""
    from .models import Base  # noqa: PLC0415 — import tardif pour éviter les circulaires

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("tables_créées")


async def drop_all() -> None:
    """Supprime toutes les tables (⚠️ dév uniquement)."""
    from .models import Base  # noqa: PLC0415

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    logger.warning("tables_supprimées")


async def get_session() -> AsyncSession:  # type: ignore[empty-body]
    """Dépendance FastAPI : fournit une session DB."""
    async with async_session() as session:
        yield session
