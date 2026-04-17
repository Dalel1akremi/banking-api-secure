import requests
import time

URL = "http://127.0.0.1:8000/auth/login"

payload = {
    "email": "testuser_fictif@example.com",
    "password": "wrongpassword"
}

print("Lancement d'une simulation d'attaque 'Brute Force' sur le Login (6 tentatives rapides)...")
print("-" * 60)

for i in range(1, 7):
    # Envoi de la requête POST
    response = requests.post(URL, json=payload)
    status = response.status_code
    
    if status == 429:
        print(f"Tentative {i} : BLOQUEE ! (Erreur HTTP {status} : {response.json().get('error', 'Rate limited')})")
    elif status == 401 or status == 404:
        print(f"Tentative {i} : Requete passee (Refusee car mot de passe incorrect HTTP {status})")
    elif status == 422:
        print(f"Tentative {i} : Erreur de validation (HTTP 422): {response.text}")
    else:
        print(f"Tentative {i} : Completee (HTTP {status})")
        
    time.sleep(0.2)  # pause de 0.2s entre chaque requête pour simuler un script rapide
