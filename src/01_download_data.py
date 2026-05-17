"""
Script para descargar el dataset de phishing desde HuggingFace.
"""

import os
import pandas as pd
from datasets import load_dataset


def download_dataset():
    print("=" * 60)
    print("DESCARGANDO DATASET DE PHISHING")
    print("=" * 60)

    print("\n[1/3] Cargando dataset desde HuggingFace...")
    try:
        dataset = load_dataset("puyang2025/seven-phishing-email-datasets")
        print("      [OK] Dataset cargado")
    except Exception as e:
        print(f"      [ERROR]: {e}")
        return False

    print("\n[2/3] Convirtiendo a DataFrame...")
    df = dataset["train"].to_pandas()
    print(f"      Total: {len(df):,}")

    print("\n[3/3] Guardando...")
    os.makedirs("data", exist_ok=True)
    output_path = "data/phishing_emails.csv"

    cols_to_keep = ["text", "subject", "label", "sender", "receiver", "dataset_name"]
    available_cols = [c for c in cols_to_keep if c in df.columns]
    df = df[available_cols]
    df.to_csv(output_path, index=False)
    print(f"      [OK]: {output_path}")

    print(f"\nTotal: {len(df):,}")
    print(f"  Legitimos (0): {(df['label'] == 0).sum():,}")
    print(f"  Phishing (1): {(df['label'] == 1).sum():,}")
    print("[OK] COMPLETO")
    return True


if __name__ == "__main__":
    download_dataset()
