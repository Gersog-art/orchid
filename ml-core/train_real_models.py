#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

def generate_training_data():
    """Генерация синтетических данных для тренировки"""
    np.random.seed(42)

    # Нормальный трафик (1000 примеров)
    normal_data = {
        'request_length': np.random.randint(200, 500, 1000),
        'param_count': np.random.randint(1, 6, 1000),
        'special_char_ratio': np.random.uniform(0.01, 0.05, 1000),
        'url_depth': np.random.randint(1, 5, 1000),
        'user_agent_length': np.random.randint(80, 150, 1000),
        'content_length': np.random.randint(100, 1000, 1000),
        'request_time_seconds': np.random.uniform(0.1, 1.0, 1000),
        'status_code': [200] * 1000
    }

    # Атаки (500 примеров)
    attack_data = {
        'request_length': np.random.randint(500, 2000, 500),
        'param_count': np.random.randint(5, 30, 500),
        'special_char_ratio': np.random.uniform(0.1, 0.5, 500),
        'url_depth': np.random.randint(5, 10, 500),
        'user_agent_length': np.random.randint(10, 60, 500),
        'content_length': np.random.randint(2000, 5000, 500),
        'request_time_seconds': np.random.uniform(1.0, 5.0, 500),
        'status_code': np.random.choice([400, 404, 500], 500)
    }

    df_normal = pd.DataFrame(normal_data)
    df_normal['label'] = 0  # 0 = нормальный
    df_normal['attack_type'] = 'normal'

    df_attack = pd.DataFrame(attack_data)
    df_attack['label'] = 1  # 1 = атака

    # Типы атак
    attack_types = ['sqli', 'xss', 'lfi', 'rce', 'brute']
    df_attack['attack_type'] = np.random.choice(attack_types, 500)

    # Объединяем
    df = pd.concat([df_normal, df_attack], ignore_index=True)

    # Перемешиваем
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    return df

def train_isolation_forest(X_train):
    """Тренировка Isolation Forest для обнаружения аномалий"""
    print("Тренировка Isolation Forest...")

    # Isolation Forest для обнаружения аномалий
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.1,  # 10% аномалий
        random_state=42,
        n_jobs=-1
    )

    iso_forest.fit(X_train)

    # Сохраняем модель
    joblib.dump(iso_forest, 'models/isolation_forest_real.joblib')
    print("✅ Isolation Forest сохранен")

    return iso_forest

def train_random_forest(X_train, y_train):
    """Тренировка Random Forest для классификации атак"""
    print("Тренировка Random Forest...")

    # Кодируем метки
    le = LabelEncoder()
    y_encoded = le.fit_transform(y_train)

    # Random Forest для классификации
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )

    rf.fit(X_train, y_encoded)

    # Сохраняем модель и encoder
    joblib.dump(rf, 'models/random_forest_real.joblib')
    joblib.dump(le, 'models/label_encoder.joblib')

    print("✅ Random Forest сохранен")
    print("✅ Label Encoder сохранен")

    return rf, le

def main():
    print("=" * 60)
    print("ТРЕНИРОВКА ML МОДЕЛЕЙ ДЛЯ ORCHID")
    print("=" * 60)

    # Создаем папку для моделей
    os.makedirs('models', exist_ok=True)
    os.makedirs('training_data', exist_ok=True)

    # Генерируем данные
    print("\nГенерация тренировочных данных...")
    df = generate_training_data()

    # Сохраняем данные
    df.to_csv('training_data/web_traffic_dataset.csv', index=False)
    print(f"✅ Данные сохранены: {len(df)} записей")

    # Подготавливаем фичи
    feature_cols = [
        'request_length', 'param_count', 'special_char_ratio',
        'url_depth', 'user_agent_length', 'content_length',
        'request_time_seconds', 'status_code'
    ]

    X = df[feature_cols]
    y = df['attack_type']

    # Масштабируем фичи
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Сохраняем scaler
    joblib.dump(scaler, 'models/scaler.joblib')
    print("✅ Scaler сохранен")

    # Разделяем данные
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42
    )

    # Тренируем модели
    iso_model = train_isolation_forest(X_train)

    # Для Random Forest используем только атаки
    attack_mask = y_train != 'normal'
    X_train_rf = X_train[attack_mask]
    y_train_rf = y_train[attack_mask]

    rf_model, le = train_random_forest(X_train_rf, y_train_rf)

    # Тестируем
    print("\n" + "=" * 60)
    print("ТЕСТИРОВАНИЕ МОДЕЛЕЙ")
    print("=" * 60)

    # Isolation Forest
    iso_preds = iso_model.predict(X_test)
    iso_anomalies = (iso_preds == -1).sum()
    print(f"Isolation Forest обнаружил {iso_anomalies} аномалий из {len(X_test)}")

    # Random Forest (только для атак)
    attack_test_mask = y_test != 'normal'
    if attack_test_mask.any():
        X_test_rf = X_test[attack_test_mask]
        y_test_rf = y_test[attack_test_mask]

        y_test_encoded = le.transform(y_test_rf)
        rf_preds = rf_model.predict(X_test_rf)

        accuracy = accuracy_score(y_test_encoded, rf_preds)
        print(f"Random Forest точность: {accuracy:.2f}")

        # Отчет по классификации
        y_pred_labels = le.inverse_transform(rf_preds)
        print("\nОтчет классификации:")
        print(classification_report(y_test_rf, y_pred_labels))

    print("\n" + "=" * 60)
    print("ВСЕ МОДЕЛИ СОХРАНЕНЫ В ПАПКУ models/")
    print("=" * 60)
    print("Файлы:")
    print("  - isolation_forest_real.joblib")
    print("  - random_forest_real.joblib")
    print("  - label_encoder.joblib")
    print("  - scaler.joblib")
    print("  - training_data/web_traffic_dataset.csv")

if __name__ == "__main__":
    main()
