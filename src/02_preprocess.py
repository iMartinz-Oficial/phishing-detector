"""
Preprocesamiento de texto para phishing detection.
"""

import os
import re
import pandas as pd
import nltk

print("Descargando stopwords...")
nltk.download("stopwords", quiet=True)

STOP_WORDS = set(nltk.corpus.stopwords.words("english"))


def clean_text(text):
    if pd.isna(text) or not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\S+|https\S+", " ", text)
    text = re.sub(r"\S+@\S+", " ", text)
    text = re.sub(r"[^a-zA-Z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    words = text.split()
    words = [w for w in words if w not in STOP_WORDS and len(w) > 2]
    return " ".join(words)


def preprocess_dataset():
    print("=" * 60)
    print("PREPROCESAMIENTO")
    print("=" * 60)

    print("\n[1/4] Cargando dataset...")
    df = pd.read_csv("data/phishing_emails.csv")
    print(f"      Emails: {len(df):,}")

    print("\n[2/4] Combinando subject + text...")
    df["combined_text"] = df["subject"].fillna("") + " " + df["text"].fillna("")

    print("\n[3/4] Preprocesando (30k muestras)...")
    df_sample = df.sample(30000, random_state=42)
    df_sample["processed_text"] = df_sample["combined_text"].apply(clean_text)
    df_sample = df_sample[df_sample["processed_text"].str.len() > 30]
    print(f"      Validos: {len(df_sample):,}")

    print("\n[4/4] Guardando...")
    os.makedirs("data", exist_ok=True)
    df_sample[["processed_text", "label", "dataset_name"]].to_csv(
        "data/processed_emails.csv", index=False
    )
    print("      [OK] COMPLETO")


if __name__ == "__main__":
    preprocess_dataset()
