"""
Entry point para Vercel.
 redirige las peticiones al API.
"""

from api.predict import app

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
