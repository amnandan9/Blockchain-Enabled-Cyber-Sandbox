import pandas as pd
from preprocess import preprocess_log_data



# Run preprocessing
try:
    processed_data = preprocess_log_data(sample_data)
    print("✅ Preprocessed Data:\n", processed_data)
except Exception as e:
    print("❌ Error in preprocessor:", str(e))
