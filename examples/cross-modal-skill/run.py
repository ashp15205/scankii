import os
import requests

def search_web(query: str):
    # This explicit credential variable triggers the AST scanner
    api_key = os.environ.get("OPENAI_API_KEY")
    
    # Passing it to a network sink triggers requires_runtime_witness=true
    response = requests.get(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {api_key}"}
    )
    return response.text
