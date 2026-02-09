from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BACKEND_DIR / "model"

VECTORIZER_PATH = MODEL_DIR / "vectorizer.pkl"
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"

