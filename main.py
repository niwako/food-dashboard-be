from fastapi import APIRouter, FastAPI
from fastapi.staticfiles import StaticFiles

from auth import router

app = FastAPI()
app.mount("/static", StaticFiles(directory="static", html=True), name="static")
api = APIRouter(prefix="/api")
api.include_router(router)
app.include_router(api)
