from deep_translator import GoogleTranslator

def risk_factor_to_numeric(risk_factor):
    """
    Convierte factores de riesgo como 'Low', 'Medium', 'High', 'Critical' en valores numéricos.
    """
    risk_mapping = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }
    return risk_mapping.get(risk_factor, 0)


def translate_text(text, target_lang="es"):
    """
    Traduce texto de inglés a español utilizando Google Translator.
    """
    if not text:
        return ""

    try:
        translated_text = GoogleTranslator(source='en', target=target_lang).translate(text)
        return translated_text
    except Exception as e:
        print(f"Error en la traducción: {e}")
        return text