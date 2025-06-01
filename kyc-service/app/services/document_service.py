from PIL import Image, ImageDraw, ImageFont
from io import BytesIO

class DocumentService:
    async def log_document_access(self, document_id: uuid.UUID, user_id: uuid.UUID, access_type: str):
        log = KycAuditLog(
            document_id=document_id,
            actor_id=user_id,
            action=f"Document {access_type}",
            actor_type="Admin",
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent"),
            access_type=access_type
        )
        self.db.add(log)
        await self.db.commit()

    async def add_watermark(self, image_bytes: bytes, user_id: uuid.UUID) -> bytes:
        image = Image.open(BytesIO(image_bytes))
        draw = ImageDraw.Draw(image)
        text = f"Viewed by {user_id} on {datetime.now()}"
        # Add watermark text to image
        draw.text((10, 10), text, fill="red")
        buffer = BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()