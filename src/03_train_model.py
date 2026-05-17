"""
Entrenamiento del modelo TF-IDF + Logistic Regression.
"""

import os
import pickle
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


def train_model():
    print("=" * 60)
    print("ENTRENAMIENTO DEL MODELO")
    print("=" * 60)

    print("\n[1/5] Cargando datos...")
    df = pd.read_csv("data/processed_emails.csv")
    print(f"      Muestras: {len(df):,}")

    print("\n[2/5] TF-IDF Vectorizer...")
    X = df["processed_text"].fillna("")
    y = df["label"]
    vectorizer = TfidfVectorizer(
        max_features=7000, ngram_range=(1, 2), min_df=3, max_df=0.9
    )
    X_tfidf = vectorizer.fit_transform(X)
    print(f"      Features: {X_tfidf.shape[1]}")

    print("\n[3/5] Dividiendo datos...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_tfidf, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n[4/5] Entrenando Logistic Regression...")
    model = LogisticRegression(
        max_iter=1000, class_weight="balanced", solver="lbfgs", C=1.0, random_state=42
    )
    model.fit(X_train, y_train)
    print("      [OK] Modelo entrenado")

    print("\n[5/5] Evaluando...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"\nAccuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1 Score:  {f1 * 100:.2f}%")

    print("\n[6/6] Guardando modelos...")
    os.makedirs("models", exist_ok=True)
    with open("models/vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)
    with open("models/model.pkl", "wb") as f:
        pickle.dump(model, f)
    print("      [OK] model.pkl y vectorizer.pkl")
    print("\n[OK] ENTRENAMIENTO COMPLETO")


if __name__ == "__main__":
    train_model()
