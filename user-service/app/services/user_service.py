import uuid
from typing import Optional, List, Dict, Any
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from datetime import datetime

from app.models.user import User, UserProfile, LoginAttempt
from app.schemas.user import UserCreate, UserProfile as UserProfileSchema, ReferralInfo
from app.utils.security import get_password_hash, verify_password

class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_user(self, user_data: UserCreate) -> User:
        """
        Create a new user with profile
        """
        # Check if email already exists
        email_query = select(User).where(User.email == user_data.email)
        email_result = await self.db.execute(email_query)
        if email_result.scalars().first() is not None:
            raise ValueError("Email already registered")
        
        # Check if phone number already exists
        phone_query = select(User).where(User.phone_number == user_data.phone_number)
        phone_result = await self.db.execute(phone_query)
        if phone_result.scalars().first() is not None:
            raise ValueError("Phone number already registered")
        
        # Create user
        hashed_password = get_password_hash(user_data.password)
        user = User(
            full_name=user_data.full_name,
            email=user_data.email,
            phone_number=user_data.phone_number,
            password_hash=hashed_password
        )
        self.db.add(user)
        
        # Generate referral code (simple implementation)
        referral_code = f"REF{uuid.uuid4().hex[:8].upper()}"
        
        # Create user profile
        profile = UserProfile(
            user=user,
            referral_code=referral_code
        )
        self.db.add(profile)
        
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def authenticate_user(self, phone_number: str, password: str) -> Optional[User]:
        """
        Authenticate user by phone number and password
        """
        query = select(User).where(User.phone_number == phone_number)
        result = await self.db.execute(query)
        user = result.scalars().first()
        
        if not user or not verify_password(password, user.password_hash):
            return None
            
        # Log login attempt
        login_attempt = LoginAttempt(
            user_id=user.id,
            ip_address="0.0.0.0",  # In real implementation, get from request
            status="Success"
        )
        self.db.add(login_attempt)
        await self.db.commit()
        
        return user
    
    async def get_user_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        """
        Get user by ID with profile
        """
        query = select(User).where(User.id == user_id).options(selectinload(User.profile))
        result = await self.db.execute(query)
        return result.scalars().first()
    
    async def update_profile(self, user_id: uuid.UUID, profile_data: UserProfileSchema) -> UserProfile:
        """
        Update user profile
        """
        query = select(UserProfile).where(UserProfile.user_id == user_id)
        result = await self.db.execute(query)
        profile = result.scalars().first()
        
        if not profile:
            raise ValueError("Profile not found")
        
        # Update profile fields
        if profile_data.dob:
            profile.dob = profile_data.dob
        if profile_data.address:
            profile.address = profile_data.address
        
        await self.db.commit()
        await self.db.refresh(profile)
        return profile
    
    async def get_referral_info(self, user_id: uuid.UUID) -> ReferralInfo:
        """
        Get user referral code and count of referred users
        """
        # Get referral code
        profile_query = select(UserProfile).where(UserProfile.user_id == user_id)
        profile_result = await self.db.execute(profile_query)
        profile = profile_result.scalars().first()
        
        if not profile:
            raise ValueError("Profile not found")
        
        # Count referred users
        count_query = select(func.count()).select_from(UserProfile).where(UserProfile.referred_by == user_id)
        count_result = await self.db.execute(count_query)
        referred_count = count_result.scalar() or 0
        
        return ReferralInfo(
            referral_code=profile.referral_code,
            referred_users_count=referred_count
        )
