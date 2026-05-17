"""
API de predicción para detección de phishing.
Compatible con Vercel Python Functions.
"""

import re
import pickle
import os
import json

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
SUSPICIOUS_URL_PATTERN = (
    r"(paypal|amazon|apple|microsoft|bank|chase|wellsfargo|citibank).*[0-9]"
)


def extract_urls(text):
    return re.findall(r"http\S+|https\S+|www\.[^\s]+", text.lower())


def analyze_urls(urls):
    if not urls:
        return 0.1, "Sin URLs detectadas"
    found_urls = []
    for url in urls:
        for tld in SUSPICIOUS_TLD:
            if tld in url:
                found_urls.append(
                    {"palabra": url[:50], "razon": f"TLD '{tld}' sospechoso"}
                )
                return 0.8, f"URL con TLD sospechoso", found_urls
        if re.search(SUSPICIOUS_URL_PATTERN, url.lower()):
            found_urls.append(
                {"palabra": url[:50], "razon": "Dominio que simula marca conocida"}
            )
            return 0.6, "URL con patrón de marca falsa", found_urls
    if len(urls) > 5:
        return 0.5, f"Muchas URLs ({len(urls)})", []
    return 0.2, f"{len(urls)} URLs normales", []


model = None
vectorizer = None


def load_models():
    global model, vectorizer
    if model is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, "..", "models", "model.pkl")
        vectorizer_path = os.path.join(base_dir, "..", "models", "vectorizer.pkl")
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


def app(environ, start_response):
    """Vercel WSGI app"""
    load_models()

    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")

    # Parse request body
    content_length = int(environ.get("CONTENT_LENGTH", 0))
    body = (
        environ.get("wsgi.input", "").read(content_length).decode("utf-8")
        if content_length > 0
        else ""
    )

    if method == "GET":
        response = {"status": "ok", "message": "Phishing Detector API"}
        response_body = json.dumps(response).encode("utf-8")
        start_response("200 OK", [("Content-Type", "application/json")])
        return [response_body]

    if method == "POST":
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}

        sender = data.get("sender", "")
        subject = data.get("subject", "")
        content = data.get("content", "")
        urls_input = data.get("urls", [])

        sender_score, sender_msg = analyze_sender(sender)
        subject_score, subject_msg = analyze_subject(subject)

        content_urls = extract_urls(content)
        all_urls = list(set(urls_input + content_urls))
        url_score, url_msg, url_words = analyze_urls(all_urls)

        processed = clean_text(content)
        if len(processed) < 20:
            content_score = 0.0
            content_msg = "Contenido muy corto"
        else:
            X = vectorizer.transform([processed])
            ml_prob = model.predict_proba(X)[0][1]
            content_score = ml_prob
            content_msg = "Contenido procesado"

        weights = {"sender": 0.15, "subject": 0.20, "content": 0.50, "urls": 0.15}
        final_score = (
            sender_score * weights["sender"]
            + subject_score * weights["subject"]
            + content_score * weights["content"]
            + url_score * weights["urls"]
        )

        if final_score > 0.6:
            label = "phishing"
            recommendation = (
                "No hacer clic en ningún enlace, no proporcionar información personal"
            )
            level = "ALTO"
        elif final_score > 0.4:
            label = "suspicious"
            recommendation = "Verificar el remitente directamente antes de actuar"
            level = "MEDIO"
        else:
            label = "legitimate"
            recommendation = "Mantén precaución habitual con cualquier email"
            level = "BAJO"

        scores = [
            ("Remitente", sender_score, sender_msg),
            ("Asunto", subject_score, subject_msg),
            ("Contenido", content_score, content_msg),
            ("Enlaces", url_score, url_msg),
        ]
        max_factor = max(scores, key=lambda x: x[1])
        factor_name = max_factor[0]
        factor_reason = max_factor[2]

        if label == "phishing":
            summary = f"""Este email presenta un nivel de riesgo {level} ({final_score * 100:.0f}%).

¿Por qué se consideró phishing?

El factor más determinante fue: *{factor_name} - {factor_reason}*

Algunas palabras del contenido aparecen en nuestra base de datos de patrones de phishing. El modelo detectó patrones similares a correos fraudulentos conocidos.

Recomendación: {recommendation}"""
        elif label == "suspicious":
            summary = f"""Este email tiene un nivel de riesgo {level} ({final_score * 100:.0f}%).

¿Por qué requiere atención?

El elemento que levantó sospecha fue: *{factor_name} - {factor_reason}*

Algunas palabras del contenido también aparecieron en nuestra base de datos de patrones de phishing. Esto no significa necesariamente que sea fraude, pero requiere verificación adicional.

Recomendación: {recommendation}"""
        else:
            summary = f"""Este email parece legítimo ({final_score * 100:.0f}% de confianza).

¿Por qué se consideró seguro?

- El dominio del remitente es normal
- El asunto no contiene palabras de urgencia
- El contenido no tiene patrones de estafas conocidos
- Las URLs presentes son razonables

Nota: Mantén precaución habitual con cualquier email, incluso los que parecen seguros.

Recomendación: {recommendation}"""

        result = {
            "score": round(final_score * 100, 1),
            "label": label,
            "details": {
                "sender": {"score": sender_score, "message": sender_msg},
                "subject": {"score": subject_score, "message": subject_msg},
                "content": {"score": content_score, "message": content_msg},
                "urls": {"score": url_score, "message": url_msg, "words": url_words},
            },
            "recommendation": recommendation,
            "summary": summary,
        }

        response_body = json.dumps(result).encode("utf-8")
        start_response("200 OK", [("Content-Type", "application/json")])
        return [response_body]

    start_response("405 Method Not Allowed", [("Content-Type", "application/json")])
    return [b'{"error": "Method not allowed"}']
