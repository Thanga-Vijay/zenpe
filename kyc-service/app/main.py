from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import kyc, admin
from app.database import create_tables
from fastapi_utils.tasks import repeat_every
from app.dependencies import get_retention_service

app = FastAPI(
    title="KYC Service API",
    description="API for KYC document upload, verification, and status checking",
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
app.include_router(kyc.router, prefix="/kyc", tags=["kyc"])
app.include_router(admin.router, prefix="/kyc/admin", tags=["admin"])

@app.on_event("startup")
async def startup():
    await create_tables()

@app.on_event("startup")
@repeat_every(seconds=60 * 60 * 24)  # Run once per day
async def cleanup_expired_documents():
    retention_service = await get_retention_service()
    await retention_service.cleanup_expired_documents()

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8002, reload=True)
