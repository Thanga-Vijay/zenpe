import asyncio
import sys
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import text

async def test_db_connection(db_url: str, service_name: str):
    """Test connection to a PostgreSQL database"""
    try:
        print(f"Testing connection to {service_name} database...")
        
        # Create engine
        engine = create_async_engine(db_url, echo=False)
        
        # Test connection with a simple query
        async with AsyncSession(engine) as session:
            result = await session.execute(text("SELECT 1"))
            value = result.scalar()
            
            if value == 1:
                print(f"âœ… Successfully connected to {service_name} database")
                return True
            else:
                print(f"âŒ Failed to execute query on {service_name} database")
                return False
    except Exception as e:
        print(f"âŒ Error connecting to {service_name} database: {str(e)}")
        return False

async def main():
    # List of services and their database URLs
    services = [
        ("User Service", "postgresql+asyncpg://postgres:password@localhost:5432/user_service"),
        ("OTP Service", "postgresql+asyncpg://postgres:password@localhost:5433/otp_service"),
        ("KYC Service", "postgresql+asyncpg://postgres:password@localhost:5434/kyc_service"),
        ("Payment Service", "postgresql+asyncpg://postgres:password@localhost:5435/payment_service"),
        ("Admin Service", "postgresql+asyncpg://postgres:password@localhost:5436/admin_service")
    ]
    
    # Test each connection
    results = []
    for service_name, db_url in services:
        result = await test_db_connection(db_url, service_name)
        results.append((service_name, result))
    
    # Print summary
    print("\n=== Connection Test Summary ===")
    all_success = True
    for service_name, success in results:
        status = "âœ… Success" if success else "âŒ Failed"
        print(f"{service_name}: {status}")
        if not success:
            all_success = False
    
    if not all_success:
        print("\nâš ï¸ Some database connections failed. Please check your PostgreSQL setup.")
        sys.exit(1)
    else:
        print("\nâœ… All database connections successful!")

if __name__ == "__main__":
    asyncio.run(main())
