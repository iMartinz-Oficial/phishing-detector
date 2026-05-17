"""
API de predicción para detección de phishing.
Compatible con Vercel Python Functions.
"""

import re
import pickle
import os

STOP_WORDS = set(
    [
        "i",
        "me",
        "my",
        "myself",
        "we",
        "our",
        "you",
        "your",
        "he",
        "she",
        "it",
        "they",
        "them",
        "this",
        "that",
        "these",
        "those",
        "am",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "may",
        "might",
        "must",
        "shall",
        "can",
        "need",
        "dare",
        "ought",
        "used",
        "to",
        "of",
        "in",
        "for",
        "on",
        "with",
        "at",
        "by",
        "from",
        "as",
        "into",
        "through",
        "during",
        "before",
        "after",
        "above",
        "below",
        "between",
        "under",
        "again",
        "further",
        "then",
        "once",
        "here",
        "there",
        "when",
        "where",
        "why",
        "how",
        "all",
        "each",
        "few",
        "more",
        "most",
        "other",
        "some",
        "such",
        "no",
        "nor",
        "not",
        "only",
        "own",
        "same",
        "so",
        "than",
        "too",
        "very",
        "s",
        "t",
        "just",
        "don",
        "now",
    ]
)

SUSPICIOUS_TLD = [
    ".xyz",
    ".top",
    ".work",
    ".click",
    ".link",
    ".online",
    ".site",
    ".buzz",
]

model = None
vectorizer = None


def load_models():
    global model, vectorizer
    if model is None:
        model_path = os.path.join(
            os.path.dirname(__file__), "..", "models", "model.pkl"
        )
        vectorizer_path = os.path.join(
            os.path.dirname(__file__), "..", "models", "vectorizer.pkl"
        )
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        with open(vectorizer_path, "rb") as f:
            vectorizer = pickle.load(f)


def clean_text(text):
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\S+|https\S+", " ", text)
    text = re.sub(r"\S+@\S+", " ", text)
    text = re.sub(r"[^a-zA-Z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    words = text.split()
    words = [w for w in words if w not in STOP_WORDS and len(w) > 2]
    return " ".join(words)


def analyze_sender(sender):
    if not sender:
        return 0.1, "No proporcionado"
    if "@" not in sender:
        return 0.3, "Formato inválido"
    domain = sender.split("@")[-1].lower()
    for tld in SUSPICIOUS_TLD:
        if domain.endswith(tld):
            return 0.8, f"Dominio sospechoso: {domain}"
    return 0.1, f"Dominio normal: {domain}"


def analyze_subject(subject):
    if not subject:
        return 0.1, "Sin asunto"
    urgency_words = [
        "urgent",
        "immediately",
        "suspend",
        "suspended",
        "expire",
        "expired",
        "locked",
        "verify",
        "confirm",
        "action required",
        "24 hours",
        "last chance",
    ]
    subject_lower = subject.lower()
    for word in urgency_words:
        if word in subject_lower:
            return 0.8, f"Palabra de urgencia: {word}"
    if len(subject) > 100:
        return 0.5, "Asunto muy largo"
    return 0.2, "Asunto normal"


def handler(request):
    """Vercel handler function"""
    load_models()

    if request.method == "GET":
        return {
            "statusCode": 200,
            "body": '{"status": "ok", "message": "Phishing Detector API"}',
        }

    if request.method == "POST":
        try:
            import json

            body = json.loads(request.body)
        except:
            body = request.json()

        sender = body.get("sender", "")
        subject = body.get("subject", "")
        content = body.get("content", "")

        sender_score, sender_msg = analyze_sender(sender)
        subject_score, subject_msg = analyze_subject(subject)

        processed = clean_text(content)
        if len(processed) < 20:
            content_score = 0.0
            content_msg = "Contenido muy corto"
        else:
            X = vectorizer.transform([processed])
            ml_prob = model.predict_proba(X)[0][1]
            content_score = ml_prob
            content_msg = "Contenido procesado"

        weights = {"sender": 0.15, "subject": 0.20, "content": 0.65}
        final_score = (
            sender_score * weights["sender"]
            + subject_score * weights["subject"]
            + content_score * weights["content"]
        )

        if final_score > 0.6:
            label = "phishing"
            recommendation = (
                "No hacer clic en ningún enlace, no proporcionar información personal"
            )
        elif final_score > 0.4:
            label = "suspicious"
            recommendation = "Verificar el remitente directamente antes de actuar"
        else:
            label = "legitimate"
            recommendation = "Mantén precaución habitual con cualquier email"

        result = {
            "score": round(final_score * 100, 1),
            "label": label,
            "details": {
                "sender": {"score": sender_score, "message": sender_msg},
                "subject": {"score": subject_score, "message": subject_msg},
                "content": {"score": content_score, "message": content_msg},
            },
            "recommendation": recommendation,
        }

        return {"statusCode": 200, "body": json.dumps(result)}

    return {"statusCode": 405, "body": "Method not allowed"}
