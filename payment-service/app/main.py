from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import payments, settlements
from app.database import create_tables

app = FastAPI(
    title="Payment and Settlement Service API",
    description="API for handling credit card to UPI payments and settlements",
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
app.include_router(payments.router, prefix="/payments", tags=["payments"])
app.include_router(settlements.router, prefix="/settlements", tags=["settlements"])

@app.on_event("startup")
async def startup():
    await create_tables()

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8003, reload=True)
