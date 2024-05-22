from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import requests


app = FastAPI(
    root_path="/api"
)


@app.get("/testtest", tags=["admin"])
async def testtest():
    return {"message": "Hello World"}
    return HTMLResponse(requests.get(url='http://localhost:26969/authorize').content)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=20)
