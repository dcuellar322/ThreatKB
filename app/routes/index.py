from app import app, auto
from flask import send_from_directory
import os


@app.route("/")
@auto.doc()
def root():
    """Root route
    Return: index.html"""
    if os.path.isfile(os.path.join(app.static_folder, "workbench", "index.html")):
        return app.send_static_file("workbench/index.html")
    return (
        "Build the frontend with npm install --prefix frontend and npm run build.",
        503,
    )


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static/images"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.get("/health")
def health():
    from app import db

    db.session.execute(db.text("SELECT 1"))
    return {"status": "ok"}
