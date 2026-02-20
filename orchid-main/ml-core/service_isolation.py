# ml-core/service_isolation.py
from fastapi import FastAPI
import joblib
import numpy as np
from pydantic import BaseModel
import time
import traceback
from typing import Dict, Any
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Orchid Isolation Forest - FULL")

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Глобальные переменные
iso_model = None
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

def load_models():
    """Загрузка моделей с проверкой"""
    global iso_model, scaler, model_loaded

    try:
        logger.info("🔄 Загрузка Isolation Forest модели...")
        iso_model = joblib.load('models/isolation_forest_real.joblib')
        logger.info("✅ Isolation Forest модель загружена")

        logger.info("🔄 Загрузка Scaler...")
        scaler = joblib.load('models/scaler.joblib')
        logger.info("✅ Scaler загружен")

        # Проверяем, что модель рабочая
        test_features = np.random.randn(1, len(feature_names))
        test_scaled = scaler.transform(test_features)
        prediction = iso_model.predict(test_scaled)
        logger.info(f"✅ Тест модели успешен, prediction shape: {prediction.shape}")

        model_loaded = True
        logger.info("✅ Все модели успешно загружены и готовы к работе")

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
        "service": "Isolation Forest (FULL)",
        "timestamp": time.time(),
        "model_loaded": model_loaded,
        "model_type": "Isolation Forest",
        "features_count": len(feature_names),
        "version": "2.0-full"
    }

@app.get("/model-info")
async def model_info():
    """Информация о модели"""
    if not model_loaded:
        return {"error": "Модель не загружена"}

    return {
        "model_type": "Isolation Forest",
        "n_estimators": iso_model.n_estimators if hasattr(iso_model, 'n_estimators') else "unknown",
        "contamination": iso_model.contamination if hasattr(iso_model, 'contamination') else "unknown",
        "features": feature_names,
        "loaded": model_loaded
    }

@app.post("/predict")
async def predict(request: PredictionRequest):
    """Полноценное предсказание с использованием ML модели"""

    if not model_loaded:
        return {
            "error": "Модель не загружена",
            "service": "Isolation Forest",
            "timestamp": time.time(),
            "model_used": False
        }

    try:
        # Извлекаем фичи в правильном порядке
        features_list = []
        missing_features = []

        for feature in feature_names:
            if feature in request.features:
                value = request.features[feature]
                try:
                    features_list.append(float(value))
                except:
                    features_list.append(0.0)  # Значение по умолчанию при ошибке
            else:
                # Если фича отсутствует, используем значение по умолчанию
                missing_features.append(feature)
                # Разумные значения по умолчанию для разных типов признаков
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
                elif feature in ['sql_keywords_count', 'html_tag_count', 'path_traversal_count']:
                    features_list.append(0.0)
                elif feature == 'entropy':
                    features_list.append(2.5)
                elif feature == 'max_token_length':
                    features_list.append(10.0)
                elif feature in ['has_equals', 'has_quotes']:
                    features_list.append(0.0)
                elif feature in ['digit_count', 'letter_count']:
                    features_list.append(5.0)
                elif feature == 'letter_digit_ratio':
                    features_list.append(1.0)
                else:
                    features_list.append(0.0)

        # Преобразуем в numpy array
        features_array = np.array([features_list])

        # Логируем для отладки
        logger.info(f"Features prepared: {features_list}")

        # Масштабируем
        features_scaled = scaler.transform(features_array)

        # Предсказание Isolation Forest
        prediction = iso_model.predict(features_scaled)[0]  # 1 = нормальный, -1 = аномалия
        anomaly_score = float(iso_model.score_samples(features_scaled)[0])

        # Определяем аномалию
        is_anomaly = bool(prediction == -1)

        # Расчёт уверенности
        if is_anomaly:
            # Для аномалий: чем меньше anomaly_score, тем выше уверенность (обычно отрицательный)
            confidence = min(0.99, max(0.5, 1.0 - abs(anomaly_score) / 10))
        else:
            # Для нормальных: обычно положительный, тоже преобразуем
            confidence = min(0.99, max(0.5, 1.0 - abs(anomaly_score) / 10))

        # Определяем тип атаки на основе комбинации фичей
        attack_type = "normal"
        if is_anomaly:
            special_char = request.features.get('special_char_ratio', 0)
            param_count = request.features.get('param_count', 0)
            url_depth = request.features.get('url_depth', 0)
            request_len = request.features.get('request_length', 0)
            status_code = request.features.get('status_code', 200)
            sql_kw = request.features.get('sql_keywords_count', 0)
            html_tags = request.features.get('html_tag_count', 0)
            path_trav = request.features.get('path_traversal_count', 0)
            has_quotes = request.features.get('has_quotes', 0)
            has_equals = request.features.get('has_equals', 0)
            entropy = request.features.get('entropy', 0)
            max_token_len = request.features.get('max_token_length', 0)
            digit_count = request.features.get('digit_count', 0)
            letter_count = request.features.get('letter_count', 0)
            letter_digit_ratio = request.features.get('letter_digit_ratio', 1.0)
            # Добавим payload и endpoint из metadata для более точных правил
            payload = str(request.metadata.get('payload', ''))
            endpoint = str(request.metadata.get('endpoint', ''))

            if sql_kw > 2 or (special_char > 0.2 and ("'" in payload or '"' in payload) and has_quotes):
                attack_type = "sqli"
            elif html_tags > 0 or (special_char > 0.25 and "<" in payload and ">" in payload):
                attack_type = "xss"
            elif path_trav > 0 or url_depth > 8 or ".." in payload or ".." in endpoint:
                attack_type = "lfi"
            elif request_len > 1500 or param_count > 12 or ";" in payload or "|" in payload:
                attack_type = "rce"
            elif status_code >= 400:
                attack_type = "error_based"
            elif entropy > 4.5 or (max_token_len > 50 and digit_count > 10):
                attack_type = "obfuscated"
            else:
                attack_type = "unknown_anomaly"

        response = {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "prediction": attack_type,
            "confidence": round(confidence, 3),
            "service": "Isolation Forest",
            "timestamp": time.time(),
            "model_used": True,
            "features_processed": len(features_list),
            "missing_features": missing_features if missing_features else None,
            "raw_prediction": int(prediction)
        }

        logger.info(f"Prediction result: {response}")
        return response

    except Exception as e:
        logger.error(f"Ошибка предсказания: {e}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Ошибка предсказания: {str(e)}",
            "service": "Isolation Forest",
            "timestamp": time.time(),
            "model_used": False
        }

@app.post("/batch-predict")
async def batch_predict(requests: list):
    """Предсказание для нескольких запросов"""
    if not model_loaded:
        return {"error": "Модель не загружена"}

    results = []
    for req in requests:
        try:
            result = await predict(req)
            results.append(result)
        except Exception as e:
            results.append({"error": str(e)})

    return {
        "results": results,
        "total": len(results),
        "anomalies": sum(1 for r in results if r.get('is_anomaly', False))
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
