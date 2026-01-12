# ml-core/service_random.py
from fastapi import FastAPI
import joblib
import numpy as np
from pydantic import BaseModel
import time
import traceback
from typing import Dict, Any
import logging

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
    'request_time_seconds', 'status_code'
]
label_mapping = {
    0: "normal",
    1: "sqli",
    2: "xss",
    3: "lfi",
    4: "rce",
    5: "brute"
}

def load_models():
    """Загрузка моделей Random Forest"""
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
        test_features = np.random.randn(1, 8)
        test_scaled = scaler.transform(test_features)
        prediction = rf_model.predict(test_scaled)
        logger.info(f"✅ Тест модели успешен, prediction: {prediction}")

        model_loaded = True
        logger.info(f"✅ Random Forest загружен. Классы: {label_encoder.classes_}")

    except Exception as e:
        logger.error(f"❌ Ошибка загрузки моделей: {e}")
        logger.error(traceback.format_exc())
        model_loaded = False

# Загружаем при старте
load_models()

class PredictionRequest(BaseModel):
    features: Dict[str, Any]
    metadata: Dict[str, Any]

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
    """Информация о модели"""
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
    """Классификация типа атаки"""

    if not model_loaded:
        return {
            "error": "Модель не загружена",
            "service": "Random Forest",
            "timestamp": time.time(),
            "model_used": False
        }

    try:
        # Извлекаем фичи
        features_list = []
        for feature in feature_names:
            if feature in request.features:
                value = request.features[feature]
                try:
                    features_list.append(float(value))
                except:
                    features_list.append(0.0)
            else:
                # Значения по умолчанию
                if feature == 'status_code':
                    features_list.append(200.0)
                elif feature == 'request_length':
                    features_list.append(500.0)
                elif feature == 'param_count':
                    features_list.append(3.0)
                elif feature == 'special_char_ratio':
                    features_list.append(0.05)
                elif feature == 'url_depth':
                    features_list.append(2.0)
                elif feature == 'user_agent_length':
                    features_list.append(120.0)
                elif feature == 'content_length':
                    features_list.append(800.0)
                elif feature == 'request_time_seconds':
                    features_list.append(0.5)
                else:
                    features_list.append(0.0)

        # Преобразуем и масштабируем
        features_array = np.array([features_list])
        features_scaled = scaler.transform(features_array)

        # Предсказание Random Forest
        prediction_encoded = rf_model.predict(features_scaled)[0]
        prediction_proba = rf_model.predict_proba(features_scaled)[0]

        # Декодируем метку
        try:
            prediction_label = label_encoder.inverse_transform([prediction_encoded])[0]
        except:
            # Если не удалось декодировать, используем mapping
            prediction_label = label_mapping.get(prediction_encoded, f"class_{prediction_encoded}")

        # Уверенность
        confidence = float(prediction_proba[prediction_encoded])

        # Определяем, является ли это атакой
        is_attack = prediction_label != "normal"

        # Получаем топ-3 предсказания
        top_n = min(3, len(prediction_proba))
        top_indices = np.argsort(prediction_proba)[-top_n:][::-1]
        top_predictions = []

        for idx in top_indices:
            try:
                label = label_encoder.inverse_transform([idx])[0]
            except:
                label = label_mapping.get(idx, f"class_{idx}")
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
