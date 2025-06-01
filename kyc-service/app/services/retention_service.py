from datetime import datetime, timedelta

class RetentionService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.retention_period = settings.DOCUMENT_RETENTION_PERIOD

    async def cleanup_expired_documents(self):
        expiry_date = datetime.now() - self.retention_period
        query = select(KycDocument).where(KycDocument.uploaded_at < expiry_date)
        results = await self.db.execute(query)
        expired_docs = results.scalars().all()

        for doc in expired_docs:
            # Archive document to long-term storage
            await self.archive_document(doc)
            # Remove from active storage
            await self.storage_service.delete_document(doc.doc_url)
            self.db.delete(doc)

        await self.db.commit()