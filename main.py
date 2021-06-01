import pandas as pd
from fastapi import APIRouter, FastAPI
from fastapi.param_functions import Depends
from fastapi.staticfiles import StaticFiles
from google.cloud import firestore

import gspread

import auth

app = FastAPI()
app.mount("/static", StaticFiles(directory="static", html=True), name="static")
api = APIRouter(prefix="/api")
api.include_router(auth.router)


@api.get("/inventory_data")
def get_inventory_data(
    gc: gspread.Client = Depends(auth.get_user_gspread_client),
    db: firestore.Client = Depends(auth.get_firestore_client),
    user=Depends(auth.get_current_user),
):
    doc_ref = db.collection("users").document(user["email"])
    doc = doc_ref.get()
    sh = gc.open_by_key(doc.to_dict()["sheet_id"])
    inventory_ws = sh.get_worksheet(0)
    return inventory_ws.get_all_records()


app.include_router(api)
