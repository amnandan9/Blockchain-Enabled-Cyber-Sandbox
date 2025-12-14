import numpy as np

# Threat categories mapping
THREAT_CATEGORIES = ["External Threat", "Internal Threat", "Invalid IP", "Unknown"]


def format_prediction(prediction_probs):
    """
    Converts model prediction probabilities into a structured report.
    
    Args:
        prediction_probs (np.ndarray): Array of probabilities from the AI model.
    
    Returns:
        dict: Readable report with categorized threat probabilities.
    """
    threat_report = {THREAT_CATEGORIES[i]: float(prediction_probs[i]) for i in range(len(THREAT_CATEGORIES))}
    
    # Determine the highest threat category
    detected_threat = THREAT_CATEGORIES[np.argmax(prediction_probs)]
    
  