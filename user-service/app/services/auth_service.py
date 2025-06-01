import uuid
import hashlib
import jwt
from datetime import datetime, timedelta
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import BlacklistedToken
from app.config import settings
from app.utils.caching import cache_result, invalidate_cache

class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_access_token(self, user_id: uuid.UUID, data: dict = None) -> str:
        """Create JWT access token for user"""
        payload = {
            "sub": str(user_id),
            "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        }
        
        if data:
            payload.update(data)
            
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")
    
    @cache_result(ttl_seconds=300)  # Cache blacklist check for 5 minutes
    async def is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted with caching"""
        # Hash the token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Check database
        query = select(BlacklistedToken).where(
            BlacklistedToken.token_hash == token_hash,
            BlacklistedToken.expires_at > datetime.utcnow()
        )
        
        result = await self.db.execute(query)
        return result.scalars().first() is not None

    async def blacklist_token(self, token: str, user_id: uuid.UUID) -> None:
        """Add token to blacklist when user logs out"""
        # Get token expiration time from payload
        try:
            payload = jwt.decode(
                token, 
                settings.JWT_SECRET_KEY, 
                algorithms=["HS256"],
                options={"verify_signature": False}  # Don't validate signature here
            )
            
            exp_timestamp = payload.get("exp", 0)
            exp_datetime = datetime.fromtimestamp(exp_timestamp)
            
            # Hash the token for security
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            # Store in database
            blacklisted_token = BlacklistedToken(
                token_hash=token_hash,
                user_id=user_id,
                expires_at=exp_datetime
            )
            
            self.db.add(blacklisted_token)
            await self.db.commit()
        except Exception as e:
            print(f"Error blacklisting token: {str(e)}")
            raise
        
        # Invalidate cache for this token
        invalidate_cache("app.services.auth_service.AuthService.is_token_blacklisted", token)
    
    async def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens from blacklist"""
        query = delete(BlacklistedToken).where(
            BlacklistedToken.expires_at < datetime.utcnow()
        )
        
        result = await self.db.execute(query)
        await self.db.commit()
        return result.rowcount
