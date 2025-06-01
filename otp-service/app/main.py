from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import otp
from app.database import create_tables

app = FastAPI(
    title="OTP Service API",
    description="API for OTP generation, sending, and verification",
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
app.include_router(otp.router, prefix="/otp", tags=["otp"])

@app.on_event("startup")
async def startup():
    await create_tables()

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8001, reload=True)
