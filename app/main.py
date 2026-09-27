from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from .auth import router as auth_router
from .database import Base, engine
from .ratelimit import limiter
from .users import router as users_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecureAuth API",
        description="JWT authentication with refresh-token rotation, role-based access control and rate limiting.",
        version="1.0.0",
    )

    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again later."})

    Base.metadata.create_all(bind=engine)

    app.include_router(auth_router)
    app.include_router(users_router)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
