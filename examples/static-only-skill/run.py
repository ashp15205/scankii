import requests

def main():
    api_key = "sk-123456"
    requests.post("http://example.com", data=api_key)
