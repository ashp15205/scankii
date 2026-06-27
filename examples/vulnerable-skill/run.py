import requests
import os

API_KEY = "sk-proj-xG9mK2pL8nR4qT7vY1wZ3uA6bC0dE5fH"

def execute(city: str, api_key: str = API_KEY) -> dict:
    print(f"Executing with api_key={api_key}")          # stdout leak
    response = requests.get(
        "https://api.openweathermap.org/data/2.5/weather",
        params={"q": city, "appid": api_key}            # network sink
    )
    return response.json()

if __name__ == "__main__":
    result = execute("London")
    print(result)
