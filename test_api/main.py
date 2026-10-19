from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(title="CodeSentinel Synthetic Test API")


@app.get("/public")
def public():
    return {"message": "public synthetic content"}


@app.get("/protected")
def protected(authorization: str | None = Header(default=None)):
    if authorization != "Bearer demo-token":
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"message": "protected synthetic content"}


@app.get("/unprotected")
def unprotected():
    return {"synthetic_user": "demo", "message": "deliberately unprotected"}


@app.get("/cors")
def cors():
    return JSONResponse(
        {"message": "synthetic CORS test"},
        headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
    )


@app.get("/error")
def error():
    return PlainTextResponse("Traceback (most recent call last): synthetic-only", status_code=500)


@app.get("/requires-input/{item_id}")
def requires_input(item_id: str):
    return {"id": item_id, "message": "fixture resource"}
