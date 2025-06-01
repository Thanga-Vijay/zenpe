from datetime import datetime
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.token import BlacklistedToken

class CleanupService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens from blacklist"""
        query = delete(BlacklistedToken).where(
            BlacklistedToken.expires_at < datetime.utcnow()
        )
        
        result = await self.db.execute(query)
        await self.db.commit()
        return result.rowcount