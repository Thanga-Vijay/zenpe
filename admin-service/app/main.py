from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import admin, notifications, audit
from app.database import create_tables

app = FastAPI(
    title="Admin and Notification Service API",
    description="API for admin operations, user notifications, and audit logging",
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
app.include_router(admin.router, prefix="/admin", tags=["admin"])
app.include_router(notifications.router, prefix="/notifications", tags=["notifications"])
app.include_router(audit.router, prefix="/admin/audit", tags=["audit"])

@app.on_event("startup")
async def startup():
    await create_tables()

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8004, reload=True)
