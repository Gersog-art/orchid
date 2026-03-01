#!/usr/bin/env python3
"""
merge_datasets.py - объединение реальных и синтетических данных
для финального обучения.
"""

import pandas as pd

REAL_DATA = 'training_data/real_attacks_dataset.csv'
SYNTHETIC_DATA = 'training_data/web_traffic_dataset_enhanced.csv'
OUTPUT_DATA = 'training_data/final_dataset.csv'

def merge():
    # Загружаем реальные данные
    real_df = pd.read_csv(REAL_DATA)
    print(f"Реальные данные: {len(real_df)} записей")

    # Загружаем синтетические
    synth_df = pd.read_csv(SYNTHETIC_DATA)
    print(f"Синтетические данные: {len(synth_df)} записей")

    # Объединяем
    combined = pd.concat([real_df, synth_df], ignore_index=True)

    # Перемешиваем
    combined = combined.sample(frac=1).reset_index(drop=True)

    # Сохраняем
    combined.to_csv(OUTPUT_DATA, index=False)
    print(f"Объединённый датасет: {len(combined)} записей")
    print("\nРаспределение по типам в объединённом датасете:")
    print(combined['attack_type'].value_counts())

    return combined

if __name__ == "__main__":
    merge()
