from fastapi import Request, HTTPException
from datetime import datetime, timedelta

class SecurityMiddleware:
    def __init__(self):
        self.sessions = {}
        self.whitelisted_ips = settings.ADMIN_WHITELISTED_IPS
        self.session_timeout = timedelta(minutes=30)

    async def __call__(self, request: Request, call_next):
        if 'admin' in request.url.path:
            await self.validate_admin_access(request)
        response = await call_next(request)
        return response

    async def validate_admin_access(self, request: Request):
        client_ip = request.client.host
        if client_ip not in self.whitelisted_ips:
            raise HTTPException(status_code=403, detail="IP not whitelisted")

        session_id = request.cookies.get('session_id')
        if not session_id or session_id not in self.sessions:
            raise HTTPException(status_code=401, detail="Session expired")

        last_activity = self.sessions[session_id]
        if datetime.now() - last_activity > self.session_timeout:
            del self.sessions[session_id]
            raise HTTPException(status_code=401, detail="Session timeout")

        self.sessions[session_id] = datetime.now()