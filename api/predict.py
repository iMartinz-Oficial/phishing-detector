"""
API de predicción para detección de phishing.
Compatible con Vercel Python Functions.
"""

import re
import pickle
import os
import json
import urllib.parse

VIRUSTOTAL_API_KEY = "95fb73b2aacb4c03eef468de781c8360a183c96745c52d92e6a9c66fb46a0f06"


def check_url_virustotal(url):
    """Verifica una URL usando la API de VirusTotal"""
    if not url or not url.startswith(("http://", "https://")):
        return None

    try:
        import requests

        vt_url = "https://www.virustotal.com/api/v3"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # First try to get existing analysis
        encoded_url = urllib.parse.quote(url, safe="")
        response = requests.get(
            f"{vt_url}/urls/{encoded_url}",
            headers=headers,
            timeout=10,
        )

        # If not found (404), submit URL for analysis
        if response.status_code == 404:
            response = requests.post(
                f"{vt_url}/urls",
                headers=headers,
                data=f"url={urllib.parse.quote(url)}",
                timeout=10,
            )
            if response.status_code == 200:
                return {
                    "status": "EN_ANALISIS",
                    "message": "URL enviada a VirusTotal, análisis en progreso...",
                    "malicious": 0,
                    "suspicious": 0,
                    "total": 0,
                }

        if response.status_code == 200:
            data = response.json()
            last_analysis = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_results", {})
            )

            malicious = 0
            suspicious = 0
            harmless = 0
            undetected = 0
            phishing_count = 0

            for engine, result in last_analysis.items():
                category = result.get("category", "")
                result_name = result.get("result", "")
                if category == "malicious" or result_name == "phishing":
                    malicious += 1
                    if result_name == "phishing":
                        phishing_count += 1
                elif category == "suspicious":
                    suspicious += 1
                elif category == "harmless":
                    harmless += 1
                else:
                    undetected += 1

            total = malicious + suspicious + harmless + undetected

            if total > 0:
                threat_score = (malicious + suspicious) / total

                if threat_score > 0.5 or phishing_count > 0:
                    status = "PELIGROSO"
                    msg = f"Detectado por {malicious + suspicious} de {total} análisis"
                    if phishing_count > 0:
                        msg += f" ({phishing_count} reportes de phishing)"
                elif threat_score > 0.1:
                    status = "SOSPECHOSO"
                    msg = f"{malicious} malicioso, {suspicious} sospechoso de {total}"
                else:
                    status = "SEGURO"
                    msg = f"{harmless} análisis seguros de {total}"

                return {
                    "status": status,
                    "message": msg,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total,
                    "phishing": phishing_count,
                }

        return {
            "status": "NO_DISPONIBLE",
            "message": "No se pudo obtener análisis",
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Error: {str(e)}",
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
        }

    return None

    try:
        import requests

        vt_url = "https://www.virustotal.com/api/v3/urls"

        encoded_url = urllib.parse.quote(url, safe="")
        response = requests.get(
            f"{vt_url}/{encoded_url}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            last_analysis = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_results", {})
            )

            malicious = 0
            suspicious = 0
            harmless = 0
            undetected = 0

            for engine, result in last_analysis.items():
                category = result.get("category", "")
                if category == "malicious":
                    malicious += 1
                elif category == "suspicious":
                    suspicious += 1
                elif category == "harmless":
                    harmless += 1
                else:
                    undetected += 1

            total = malicious + suspicious + harmless + undetected
            if total > 0:
                threat_score = (malicious + suspicious) / total

                if threat_score > 0.5:
                    status = "PELIGROSO"
                    message = (
                        f"Detectado por {malicious + suspicious} de {total} análisis"
                    )
                elif threat_score > 0.1:
                    status = "SOSPECHOSO"
                    message = f"{malicious} malicious, {suspicious} suspicious de {total} análisis"
                else:
                    status = "SEGURO"
                    message = f"{harmless} análisis seguros de {total}"

                return {
                    "status": status,
                    "message": message,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total,
                }
        elif response.status_code == 404:
            return {
                "status": "NO_ANALIZADO",
                "message": "URL no encontrada en VirusTotal, iniciando análisis...",
                "malicious": 0,
                "suspicious": 0,
                "total": 0,
            }
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Error al verificar: {str(e)}",
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
        }

    return None


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
        return 0.1, "Sin URLs detectadas", [], []

    url_details = []
    vt_results = []
    max_score = 0.1

    for url in urls:
        url_info = {"url": url, "analysis": {}, "heuristic_score": 0}

        for tld in SUSPICIOUS_TLD:
            if tld in url.lower():
                url_info["heuristic_score"] = 0.9
                url_info["analysis"]["tld"] = {"detected": True, "tld": tld}
                break

        if url_info["heuristic_score"] == 0 and re.search(
            SUSPICIOUS_URL_PATTERN, url.lower()
        ):
            url_info["heuristic_score"] = 0.7
            url_info["analysis"]["brand_impersonation"] = {"detected": True}

        vt_result = check_url_virustotal(url)
        if vt_result:
            url_info["analysis"]["virustotal"] = vt_result

            if vt_result["status"] == "PELIGROSO":
                url_info["virustotal_score"] = 0.95
            elif vt_result["status"] == "SOSPECHOSO":
                url_info["virustotal_score"] = 0.6
            elif vt_result["status"] == "SEGURO":
                url_info["virustotal_score"] = 0.05
            else:
                url_info["virustotal_score"] = 0.3
        else:
            url_info["virustotal_score"] = 0

        url_score = max(
            url_info["heuristic_score"], url_info.get("virustotal_score", 0)
        )
        url_info["final_score"] = url_score

        if url_score > max_score:
            max_score = url_score

        url_details.append(url_info)

        if vt_result:
            vt_results.append({"url": url, "result": vt_result})

    if len(urls) > 5:
        return 0.5, f"Demasiadas URLs ({len(urls)})", url_details, vt_results

    if max_score >= 0.8:
        return max_score, "URLs peligrosas detectadas", url_details, vt_results
    elif max_score >= 0.5:
        return max_score, "URLs sospechosas detectadas", url_details, vt_results
    elif max_score >= 0.3:
        return max_score, "Algunas URLs requieren atención", url_details, vt_results
    else:
        return max_score, "URLs parecen seguras", url_details, vt_results


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
        return 0.3, "Formato de email inválido"
    domain = sender.split("@")[-1].lower()
    for tld in SUSPICIOUS_TLD:
        if domain.endswith(tld):
            return 0.8, f"Dominio sospechoso"
    return 0.1, "Dominio normal"


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
            return 0.8, f"Palabra de urgencia detectada"
    if len(subject) > 100:
        return 0.5, "Asunto excesivamente largo"
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
        url_score, url_msg, url_details, vt_results = analyze_urls(all_urls)

        processed = clean_text(content)
        if len(processed) < 20:
            content_score = 0.0
            content_msg = "Contenido muy corto para analizar"
        else:
            X = vectorizer.transform([processed])
            ml_prob = model.predict_proba(X)[0][1]
            content_score = ml_prob
            if ml_prob > 0.6:
                content_msg = "Patrones de phishing detectados"
            elif ml_prob > 0.4:
                content_msg = "Contenido sospechoso"
            else:
                content_msg = "Contenido normal"

        weights = {"sender": 0.10, "subject": 0.15, "content": 0.40, "urls": 0.35}
        final_score = (
            sender_score * weights["sender"]
            + subject_score * weights["subject"]
            + content_score * weights["content"]
            + url_score * weights["urls"]
        )

        evaluations = {
            "remitente": {
                "score": sender_score,
                "message": sender_msg,
                "nombre": "Remitente",
            },
            "asunto": {
                "score": subject_score,
                "message": subject_msg,
                "nombre": "Asunto",
            },
            "contenido": {
                "score": content_score,
                "message": content_msg,
                "nombre": "Contenido del Email",
            },
            "enlaces": {
                "score": url_score,
                "message": url_msg,
                "nombre": "Análisis de Enlaces",
            },
        }

        if final_score > 0.6:
            label = "phishing"
            level = "ALTO"
            concerns = []
            if sender_score > 0.5:
                concerns.append("El dominio del remitente es sospechoso")
            if subject_score > 0.5:
                concerns.append(
                    "El asunto contiene palabras de urgencia o manipulación"
                )
            if content_score > 0.5:
                concerns.append("El contenido del email tiene patrones de phishing")
            if url_score > 0.5:
                concerns.append(
                    "Los enlaces han sido marcados como peligrosos porVirusTotal"
                )
            recommendation = "⚠️ NO hagas clic en ningún enlace. ⚠️ No proporciones información personal. ⚠️ Verifica el remitente contactándolo por otros medios."
        elif final_score > 0.4:
            label = "suspicious"
            level = "MEDIO"
            concerns = []
            if sender_score > 0.3:
                concerns.append("El dominio del remitente parece inusual")
            if subject_score > 0.3:
                concerns.append(
                    "El asunto tiene algunas palabras que suelen usar losphishing"
                )
            if content_score > 0.3:
                concerns.append(
                    "El contenido tiene algunas características suspechosas"
                )
            if url_score > 0.3:
                concerns.append("Algunos enlaces requieren más verificación")
            recommendation = "⚠️ Verifica el remitente directamente antes de actuar. ⚠️ No proporcion datos sensibles."
        else:
            label = "legitimate"
            level = "BAJO"
            concerns = []
            recommendation = "✅ El email parece legítimo, pero mantén precaución habitualcon cualquier correo."

        eval_details = ""
        for key, eval in evaluations.items():
            status = (
                "🔴" if eval["score"] > 0.5 else "🟡" if eval["score"] > 0.3 else "🟢"
            )
            eval_details += f"{status} *{eval['nombre']}:* {eval['message']}\n"

        if label == "phishing":
            summary = f"""📊 *RESUMEN DEL ANÁLISIS*

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVEL DE RIESGO: {level} ({final_score * 100:.0f}%)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 *EVALUACIÓN DE CADA COMPONENTE:*

{eval_details}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ *¿POR QUÉ SE CONSIDERA PHISHING?*

El análisis detecto múltiples señales de alerta:
{chr(10).join("- " + c for c in concerns)}

🔍 *Fuentes que contribuyeron al diagnóstico:*
• Modelo ML (TF-IDF + Logistic Regression): {content_score * 100:.0f}%
• Análisis de VirusTotal: {url_score * 100:.0f}%
• Patrones en asunto: {subject_score * 100:.0f}%
• Reputación del dominio: {sender_score * 100:.0f}%

💡 *MEDIDAS RECOMENDADAS:*
{recommendation}"""
        elif label == "suspicious":
            summary = f"""📊 *RESUMEN DEL ANÁLISIS*

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVEL DE RIESGO: {level} ({final_score * 100:.0f}%)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 *EVALUACIÓN DE CADA COMPONENTE:*

{eval_details}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ *¿POR QUÉ REQUIERE ATENCIÓN?*

Se detectaron algunas señales sospechosas:
{chr(10).join("- " + c for c in concerns)}

🔍 *Fuentes que contribuyeron:*
• Modelo ML (TF-IDF + Logistic Regression): {content_score * 100:.0f}%
• Análisis de VirusTotal: {url_score * 100:.0f}%
• Patrones en asunto: {subject_score * 100:.0f}%
• Reputación del dominio: {sender_score * 100:.0f}%

💡 *MEDIDAS RECOMENDADAS:*
{recommendation}"""
        else:
            summary = f"""📊 *RESUMEN DEL ANÁLISIS*

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIVEL DE RIESGO: {level} ({final_score * 100:.0f}%)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 *EVALUACIÓN DE CADA COMPONENTE:*

{eval_details}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ *¿POR QUÉ SE CONSIDERÓ SEGURO?*

Todos los componentes pasaron las pruebas:
• Dominio del remitente: Normal
• Asunto: Sin palabras de urgencia
• Contenido: Sin patrones de phishing
• Enlaces: Verificados como seguros (VirusTotal)

🔍 *Fuentes verificadas:*
• Modelo ML (TF-IDF + Logistic Regression): {content_score * 100:.0f}%
• Análisis de VirusTotal: {url_score * 100:.0f}%
• Patrones en asunto: {subject_score * 100:.0f}%
• Reputación del dominio: {sender_score * 100:.0f}%

💡 *NOTA:*
Mantén precaución habitual con cualquier email, incluso los que parecen seguros.

{recommendation}"""

        result = {
            "score": round(final_score * 100, 1),
            "label": label,
            "level": level,
            "details": {
                "remitente": {
                    "score": sender_score,
                    "message": sender_msg,
                    "nombre": "Remitente",
                },
                "asunto": {
                    "score": subject_score,
                    "message": subject_msg,
                    "nombre": "Asunto",
                },
                "contenido": {
                    "score": content_score,
                    "message": content_msg,
                    "nombre": "Contenido",
                },
                "enlaces": {
                    "score": url_score,
                    "message": url_msg,
                    "details": url_details,
                    "nombre": "Enlaces",
                },
            },
            "virustotal": vt_results,
            "recommendation": recommendation,
            "summary": summary,
            "components": {
                "ml_model": {
                    "score": round(content_score * 100, 1),
                    "weight": weights["content"] * 100,
                },
                "virustotal": {
                    "score": round(url_score * 100, 1),
                    "weight": weights["urls"] * 100,
                },
                "subject_analysis": {
                    "score": round(subject_score * 100, 1),
                    "weight": weights["subject"] * 100,
                },
                "sender_analysis": {
                    "score": round(sender_score * 100, 1),
                    "weight": weights["sender"] * 100,
                },
            },
        }

        response_body = json.dumps(result).encode("utf-8")
        start_response("200 OK", [("Content-Type", "application/json")])
        return [response_body]

    start_response("405 Method Not Allowed", [("Content-Type", "application/json")])
    return [b'{"error": "Method not allowed"}']
