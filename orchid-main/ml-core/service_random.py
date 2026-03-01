# ml-core/service_random.py
from fastapi import FastAPI
import joblib
import numpy as np
from pydantic import BaseModel
import time
import traceback
from typing import Dict, Any
import logging
from concurrent.futures import ThreadPoolExecutor
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Orchid Random Forest - FULL")

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Глобальные переменные
rf_model = None
label_encoder = None
scaler = None
model_loaded = False
feature_names = [
    'request_length', 'param_count', 'special_char_ratio',
    'url_depth', 'user_agent_length', 'content_length',
    'request_time_seconds', 'status_code',
    'sql_keywords_count', 'html_tag_count', 'path_traversal_count',
    'entropy', 'max_token_length', 'has_equals', 'has_quotes',
    'digit_count', 'letter_count', 'letter_digit_ratio'
]

# Увеличенный пул потоков
executor = ThreadPoolExecutor(max_workers=16)

class PredictionRequest(BaseModel):
    features: Dict[str, Any]
    metadata: Dict[str, Any]

def load_models():
    global rf_model, label_encoder, scaler, model_loaded
    try:
        logger.info("🔄 Загрузка Random Forest модели...")
        rf_model = joblib.load('models/random_forest_real.joblib')
        logger.info("✅ Random Forest модель загружена")

        logger.info("🔄 Загрузка Label Encoder...")
        label_encoder = joblib.load('models/label_encoder.joblib')
        logger.info("✅ Label Encoder загружен")

        logger.info("🔄 Загрузка Scaler...")
        scaler = joblib.load('models/scaler.joblib')
        logger.info("✅ Scaler загружен")

        # Тест модели
        test_features = np.random.randn(1, 18)
        test_scaled = scaler.transform(test_features)
        prediction = rf_model.predict(test_scaled)
        logger.info(f"✅ Тест модели успешен, prediction: {prediction}")

        model_loaded = True
        logger.info(f"✅ Random Forest загружен. Классы: {label_encoder.classes_}")
    except Exception as e:
        logger.error(f"❌ Ошибка загрузки моделей: {e}")
        logger.error(traceback.format_exc())
        model_loaded = False

load_models()

@app.get("/health")
async def health():
    return {
        "status": "healthy" if model_loaded else "unhealthy",
        "service": "Random Forest (FULL)",
        "timestamp": time.time(),
        "model_loaded": model_loaded,
        "model_type": "Random Forest",
        "n_classes": len(label_encoder.classes_) if label_encoder else 0,
        "version": "2.0-full"
    }

@app.get("/model-info")
async def model_info():
    if not model_loaded:
        return {"error": "Модель не загружена"}
    return {
        "model_type": "Random Forest",
        "n_estimators": rf_model.n_estimators if hasattr(rf_model, 'n_estimators') else "unknown",
        "n_classes": len(label_encoder.classes_) if label_encoder else "unknown",
        "classes": list(label_encoder.classes_) if label_encoder else [],
        "features": feature_names,
        "loaded": model_loaded
    }

@app.post("/predict")
async def predict(request: PredictionRequest):
    if not model_loaded:
        return {
            "error": "Модель не загружена",
            "service": "Random Forest",
            "timestamp": time.time(),
            "model_used": False
        }

    loop = asyncio.get_event_loop()
    try:
        # Извлекаем фичи
        features_list = []
        for feature in feature_names:
            if feature in request.features:
                value = request.features[feature]
                try:
                    # Защита от inf/nan
                    val = float(value)
                    if np.isinf(val) or np.isnan(val):
                        val = 0.0
                    features_list.append(val)
                except:
                    features_list.append(0.0)
            else:
                # Значения по умолчанию
                defaults = {
                    'status_code': 200.0,
                    'request_length': 500.0,
                    'param_count': 3.0,
                    'special_char_ratio': 0.05,
                    'url_depth': 2.0,
                    'user_agent_length': 120.0,
                    'content_length': 800.0,
                    'request_time_seconds': 0.5,
                    'sql_keywords_count': 0.0,
                    'html_tag_count': 0.0,
                    'path_traversal_count': 0.0,
                    'entropy': 2.5,
                    'max_token_length': 10.0,
                    'has_equals': 0.0,
                    'has_quotes': 0.0,
                    'digit_count': 5.0,
                    'letter_count': 5.0,
                    'letter_digit_ratio': 1.0
                }
                features_list.append(defaults.get(feature, 0.0))

        # Преобразуем в numpy array
        features_array = np.array([features_list])

        # Масштабируем в пуле потоков
        features_scaled = await loop.run_in_executor(executor, scaler.transform, features_array)

        # Предсказания
        prediction_encoded = await loop.run_in_executor(executor, rf_model.predict, features_scaled)
        prediction_proba = await loop.run_in_executor(executor, rf_model.predict_proba, features_scaled)

        prediction_encoded = prediction_encoded[0]
        prediction_proba = prediction_proba[0]

        # Декодируем метку
        try:
            prediction_label = label_encoder.inverse_transform([prediction_encoded])[0]
        except:
            prediction_label = f"class_{prediction_encoded}"

        confidence = float(prediction_proba[prediction_encoded])
        is_attack = prediction_label != "normal"

        # Топ-3
        top_n = min(3, len(prediction_proba))
        top_indices = np.argsort(prediction_proba)[-top_n:][::-1]
        top_predictions = []
        for idx in top_indices:
            try:
                label = label_encoder.inverse_transform([idx])[0]
            except:
                label = f"class_{idx}"
            top_predictions.append({
                "label": label,
                "confidence": float(prediction_proba[idx]),
                "class_id": int(idx)
            })

        response = {
            "prediction": prediction_label,
            "confidence": round(confidence, 3),
            "is_attack": is_attack,
            "service": "Random Forest",
            "timestamp": time.time(),
            "model_used": True,
            "top_predictions": top_predictions,
            "all_probabilities": {
                label_encoder.inverse_transform([i])[0]: float(prediction_proba[i])
                for i in range(len(prediction_proba))
            } if label_encoder else {},
            "raw_features": features_list
        }

        logger.info(f"Random Forest prediction: {response}")
        return response

    except Exception as e:
        logger.error(f"Ошибка предсказания: {e}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Ошибка предсказания: {str(e)}",
            "service": "Random Forest",
            "timestamp": time.time(),
            "model_used": False
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
