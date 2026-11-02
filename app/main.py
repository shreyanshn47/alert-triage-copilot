from fastapi import FastAPI

app = FastAPI(title="Alert Triage Copilot", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check. Later steps can extend this with a DB ping."""
    return {"status": "ok"}
