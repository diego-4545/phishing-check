import hashlib
import os

VERDICTS = ("phishing", "sospechoso", "legitimo", "no_es_correo")


class AnalysisError(Exception):
    """Error controlado al analizar o al validar la respuesta."""


def validate_result(data):
    """Valida el JSON contra un esquema estricto y devuelve una copia limpia."""
    if not isinstance(data, dict):
        raise AnalysisError("Formato de respuesta inválido.")

    verdict = data.get("veredicto")
    confidence = data.get("confianza")
    signals = data.get("senales")
    recommendation = data.get("recomendacion")

    if verdict not in VERDICTS:
        raise AnalysisError("Veredicto fuera de la lista permitida.")
    if isinstance(confidence, bool) or not isinstance(confidence, int) \
            or not 0 <= confidence <= 100:
        raise AnalysisError("Confianza fuera de rango.")
    if not isinstance(signals, list) or not all(isinstance(s, str) for s in signals):
        raise AnalysisError("Señales inválidas.")
    if not isinstance(recommendation, str) or not recommendation.strip():
        raise AnalysisError("Recomendación inválida.")

    return {
        "veredicto": verdict,
        "confianza": confidence,
        "senales": [s.strip()[:200] for s in signals[:8]],
        "recomendacion": recommendation.strip()[:500],
    }


_MOCKS = [
    {
        "veredicto": "phishing",
        "confianza": 92,
        "senales": [
            "El dominio del remitente no coincide con la empresa que dice ser",
            "Urgencia artificial: amenaza con cerrar la cuenta en 24 horas",
            "Enlace acortado que oculta el destino real",
        ],
        "recomendacion": "No abras el enlace ni descargues adjuntos. Reporta el correo a TI y bórralo.",
    },
    {
        "veredicto": "sospechoso",
        "confianza": 61,
        "senales": [
            "Saludo genérico en lugar de tu nombre",
            "Solicita confirmar datos personales por correo",
        ],
        "recomendacion": "Verifica con la empresa por un canal oficial antes de responder o hacer clic.",
    },
    {
        "veredicto": "legitimo",
        "confianza": 84,
        "senales": [
            "El dominio del remitente coincide con la organización",
            "No contiene enlaces acortados ni solicitudes urgentes",
        ],
        "recomendacion": "No se detectaron señales claras de phishing, pero mantén la precaución habitual.",
    },
]


_NOT_EMAIL = {
    "veredicto": "no_es_correo",
    "confianza": 90,
    "senales": [],
    "recomendacion": "La imagen no parece ser la captura de un correo electrónico.",
}


def _mock(image_bytes, filename):
    if "no-correo" in (filename or "").lower():
        return _NOT_EMAIL
    # Misma imagen = mismo resultado; imágenes distintas varían el veredicto.
    idx = hashlib.sha256(image_bytes).digest()[0] % len(_MOCKS)
    return _MOCKS[idx]


def analyze_image(image_bytes, mime_type, filename=""):
    if os.environ.get("MOCK_MODE", "true").lower() == "true":
        raw = _mock(image_bytes, filename)
    else:
        raise AnalysisError("El modo real se implementa en el siguiente paso.")
    return validate_result(raw)