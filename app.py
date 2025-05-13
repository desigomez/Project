from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import numpy as np
import re
from scipy.sparse import lil_matrix


# Define the custom tokenizer 
def custom_tokenizer(text):
    text = re.sub(r"(['\";=])", r" \1 ", text) 
    text = re.sub(r"--", " -- ", text)          
    text = re.sub(r"\s+", " ", text)            
    text = text.lower()
    return text.strip().split()

# Load the trained model and vectorizer
svm_model = joblib.load("svm_model.pkl")
vectorizer = joblib.load("vectorizer.pkl") 

# Flask App Initialization
app = Flask(__name__)
CORS(app)  

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['POST'])
def detect_sql_injection():
    try:
        data = request.json
        sql_query = data.get("sql_query", "")
        model_type = data.get("model_type", "svm")

        if not sql_query:
            return jsonify({"error": "No query provided"}), 400

        if model_type != "svm":
            return jsonify({"error": "Invalid model_type. Only 'svm' is supported."}), 400

        # Transform query using vectorizer
        query_vector = vectorizer.transform([sql_query])

        # Ensure vector dimensions match model expectations
        model_expected_shape = svm_model.support_vectors_.shape[1]

        if query_vector.shape[1] < model_expected_shape:
            padded_query_vector = lil_matrix((1, model_expected_shape))
            padded_query_vector[:, :query_vector.shape[1]] = query_vector
        else:
            padded_query_vector = query_vector

        # Prediction
        prediction = svm_model.predict(padded_query_vector)
        result = "Malicious" if prediction[0] == 1 else "Safe"

        return jsonify({
            "query": sql_query,
            "classification": result
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/check_login', methods=['POST'])
def check_login():
    try:
        data = request.json
        username = data.get("username", "")
        password = data.get("password", "")

        # Combine user inputs
        combined_input = f"{username} {password}"
        print("Combined user input:", combined_input)

        # Tokenize and vectorize the input
        tokens = custom_tokenizer(combined_input)
        tokenized_input = " ".join(tokens)
        print("Tokenized input:", tokenized_input)

        query_vector = vectorizer.transform([tokenized_input])
        print("Vector shape:", query_vector.shape)

        # Padding if vector is smaller than model expects
        model_expected_shape = svm_model.support_vectors_.shape[1]
        if query_vector.shape[1] < model_expected_shape:
            from scipy.sparse import lil_matrix
            padded_query_vector = lil_matrix((1, model_expected_shape))
            padded_query_vector[:, :query_vector.shape[1]] = query_vector
        else:
            padded_query_vector = query_vector

        # Make prediction
        prediction = svm_model.predict(padded_query_vector)
        result = "Malicious" if prediction[0] == 1 else "Safe"

        simulated_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        return jsonify({
            "classification": result,
            "simulated_query": simulated_query,
            "debug": {
                "tokenized_input": tokenized_input
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)