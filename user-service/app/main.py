import asyncio
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.routers import users
from app.database import create_tables, engine
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.auth_service import AuthService

app = FastAPI(
    title="User Service API",
    description="API for user management and authentication",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(users.router, prefix="/users", tags=["users"])

# Add a background task to clean up expired tokens
@app.on_event("startup")
async def startup():
    await create_tables()
    
    # Schedule token cleanup task
    async def cleanup_tokens_task():
        while True:
            db = AsyncSession(engine)
            try:
                auth_service = AuthService(db)
                count = await auth_service.cleanup_expired_tokens()
                print(f"Cleaned up {count} expired tokens")
            except Exception as e:
                print(f"Error in token cleanup: {str(e)}")
            finally:
                await db.close()
            
            # Run once a day
            await asyncio.sleep(24 * 60 * 60)
    
    # Start background task
    asyncio.create_task(cleanup_tokens_task())

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
