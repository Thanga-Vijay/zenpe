import uuid
import os
import boto3
from fastapi import UploadFile
from typing import Optional
from app.config import settings

class StorageService:
    def __init__(self):
        # Initialize AWS S3 client
        self.s3 = boto3.client(
            's3',
            region_name=settings.AWS_REGION
        )
        self.bucket = settings.AWS_S3_BUCKET
    
    async def upload_document(self, file: UploadFile, path: str) -> str:
        """
        Upload document to S3
        """
        file_content = await file.read()
        file_ext = os.path.splitext(file.filename)[1]
        file_key = f"{path}/{uuid.uuid4()}{file_ext}"
        
        # For local development, you might want to save to disk instead
        # Uncomment this if needed:
        """
        os.makedirs(os.path.dirname(f"./uploads/{file_key}"), exist_ok=True)
        with open(f"./uploads/{file_key}", "wb") as f:
            f.write(file_content)
        return f"./uploads/{file_key}"
        """
        
        # Upload to S3
        try:
            self.s3.put_object(
                Bucket=self.bucket,
                Key=file_key,
                Body=file_content,
                ContentType=file.content_type
            )
            
            # Generate S3 URL
            url = f"https://{self.bucket}.s3.{settings.AWS_REGION}.amazonaws.com/{file_key}"
            return url
        except Exception as e:
            # In production, handle S3 errors properly
            print(f"Error uploading to S3: {str(e)}")
            # For development, save locally as fallback
            os.makedirs("./uploads", exist_ok=True)
            with open(f"./uploads/{uuid.uuid4()}{file_ext}", "wb") as f:
                await file.seek(0)
                f.write(await file.read())
            return f"local://uploads/{uuid.uuid4()}{file_ext}"
    
    def get_document_url(self, file_key: str) -> str:
        """
        Get document URL from S3
        """
        return f"https://{self.bucket}.s3.{settings.AWS_REGION}.amazonaws.com/{file_key}"
    
    async def delete_document(self, file_key: str) -> bool:
        """
        Delete document from S3
        """
        try:
            self.s3.delete_object(
                Bucket=self.bucket,
                Key=file_key
            )
            return True
        except Exception as e:
            print(f"Error deleting from S3: {str(e)}")
            return False
