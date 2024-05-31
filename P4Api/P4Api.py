from typing import Union
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import json
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/decode")
async def decode():
    with open('D:\shared\cms.json', 'r') as file:
        return json.load(file)
    

if __name__ == '__main__':
    uvicorn.run(app=app, host="10.133.72.190", port=8000)