import joblib
from functools import lru_cache
from ..core.config import MODEL_PATH, VECTORIZER_PATH

@lru_cache(maxsize=1)
def load_ml():
    vectorizer = joblib.load(VECTORIZER_PATH)
    model = joblib.load(MODEL_PATH)
    return vectorizer, model