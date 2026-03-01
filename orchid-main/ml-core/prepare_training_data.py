#!/usr/bin/env python3
"""
prepare_training_data.py - выгрузка данных из attacks.db
и преобразование в формат для обучения моделей.
"""

import sqlite3
import pandas as pd
import json
import os
from datetime import datetime

DB_PATH = '../data/attacks.db'
OUTPUT_CSV = 'training_data/real_attacks_dataset.csv'

def load_and_prepare():
    # Подключаемся к БД
    conn = sqlite3.connect(DB_PATH)

    # Загружаем атаки (detected = 1) и нормальные запросы (detected = 0)
    # Но у нас в БД все запросы помечены как атаки, даже если ML сказал normal.
    # Поэтому будем использовать предсказание Random Forest как истинную метку,
    # если оно есть, иначе метку из isolation_result.
    query = """
    SELECT
        timestamp,
        attack_type as ml_attack_type,
        endpoint,
        payload,
        http_method,
        user_agent,
        real_response_status,
        isolation_result,
        random_result,
        detected
    FROM attacks
    WHERE payload IS NOT NULL AND payload != ''
    ORDER BY timestamp DESC
    LIMIT 20000  -- ограничим, чтобы не перегружать, можно убрать
    """

    df = pd.read_sql_query(query, conn)
    conn.close()

    print(f"Загружено {len(df)} записей из БД")

    # Функция извлечения признаков (скопируем из async_monitor.py)
    import math
    import re

    def extract_features_from_row(row):
        payload = row['payload'] or ''
        endpoint = row['endpoint'] or ''
        method = row['http_method'] or 'GET'
        user_agent = row['user_agent'] or 'Mozilla/5.0'

        # Базовые
        request_length = len(endpoint) + len(payload)
        param_count = payload.count('&') + (1 if '?' in payload else 0) + (1 if method == 'POST' else 0)
        special_chars = sum(1 for c in payload if c in "'\"<>();%&|`$")
        special_char_ratio = special_chars / (len(payload) + 1)
        url_depth = endpoint.count('/')
        user_agent_length = len(user_agent)
        content_length = len(payload) if method == 'POST' else 0
        request_time_seconds = 0.5  # заглушка, можно не использовать

        # HTTP статус из реального ответа
        status_code = row['real_response_status'] or 200

        # Признаки из payload
        sql_keywords = ['select', 'union', 'insert', 'delete', 'update', 'drop', 'alter',
                        'where', 'from', 'order by', 'group by', 'having', 'join', 'on',
                        'and', 'or', 'not', 'null', '--', '#', '/*']
        sql_keywords_count = 0
        payload_lower = payload.lower()
        for kw in sql_keywords:
            sql_keywords_count += payload_lower.count(kw)

        html_tags = re.findall(r'<[^>]+>', payload)
        html_tag_count = len(html_tags)

        path_traversal_count = payload.count('../') + payload.count('..\\') + payload.count('..%2f')

        if payload:
            prob = [float(payload.count(c)) / len(payload) for c in set(payload)]
            entropy = -sum([p * math.log2(p) for p in prob])
        else:
            entropy = 0

        tokens = re.split(r'[^a-zA-Z0-9]', payload)
        max_token_length = max((len(t) for t in tokens), default=0)

        has_equals = 1 if '=' in payload else 0
        has_quotes = 1 if ("'" in payload or '"' in payload) else 0

        digit_count = sum(c.isdigit() for c in payload)
        letter_count = sum(c.isalpha() for c in payload)
        letter_digit_ratio = letter_count / (digit_count + 1) if digit_count > 0 else float('inf')

        features = {
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
            'letter_digit_ratio': round(letter_digit_ratio, 4) if letter_digit_ratio != float('inf') else 0.0
        }
        return features

    # Извлекаем признаки для каждой строки
    features_list = []
    attack_types = []

    for idx, row in df.iterrows():
        try:
            feats = extract_features_from_row(row)
            features_list.append(feats)

            # Определяем истинную метку
            # Сначала пробуем взять из random_result
            attack_type = 'unknown'
            if row['random_result'] and row['random_result'] != 'null':
                try:
                    rf = json.loads(row['random_result'])
                    if 'prediction' in rf and rf['prediction'] != 'unknown':
                        attack_type = rf['prediction']
                except:
                    pass

            if attack_type == 'unknown' and row['isolation_result']:
                try:
                    iso = json.loads(row['isolation_result'])
                    if iso.get('is_anomaly') and 'prediction' in iso:
                        attack_type = iso['prediction']
                except:
                    pass

            # Если всё ещё unknown, используем поле attack_type из БД
            if attack_type == 'unknown':
                attack_type = row['ml_attack_type'] or 'normal'

            attack_types.append(attack_type)

        except Exception as e:
            print(f"Ошибка обработки строки {idx}: {e}")
            continue

    result_df = pd.DataFrame(features_list)
    result_df['attack_type'] = attack_types

    # Сохраняем
    os.makedirs('training_data', exist_ok=True)
    result_df.to_csv(OUTPUT_CSV, index=False)
    print(f"Сохранено {len(result_df)} записей в {OUTPUT_CSV}")
    print("\nРаспределение по типам:")
    print(result_df['attack_type'].value_counts())

    return result_df

if __name__ == "__main__":
    load_and_prepare()
