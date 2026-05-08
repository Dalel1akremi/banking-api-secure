import requests
import time
import statistics
import urllib3

# Desactiver les avertissements SSL pour les certificats auto-signes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration du test
URL = "https://localhost/api/accounts"
# On garde les certificats clients pour que NGINX accepte la connexion (mTLS)
CERTS = ('nginx_certs/client.crt', 'nginx_certs/client.key')

# Nombre de requêtes pour la statistique
NB_REQUESTS = 50

print(f"--- Benchmark de Performance API ---")
print(f"Cible : {URL}")
print(f"Nombre de requetes : {NB_REQUESTS}")
print(f"mTLS Client Certs : ACTIF")
print("-" * 40)

latencies = []

try:
    for i in range(1, NB_REQUESTS + 1):
        start_time = time.perf_counter()
        
        # verify=False permet de passer outre l'erreur "self-signed certificate"
        # tout en envoyant quand même les certificats mTLS (cert=CERTS)
        response = requests.get(URL, cert=CERTS, verify=False, timeout=5)
        
        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000
        latencies.append(latency_ms)
        
        if i % 10 == 0:
            print(f"Progression : {i}/{NB_REQUESTS} requetes effectuees...")

    # Calcul des statistiques
    avg_latency = statistics.mean(latencies)
    min_latency = min(latencies)
    max_latency = max(latencies)

    print("-" * 40)
    print(f"RESULTATS :")
    print(f"  - Latence Moyenne : {avg_latency:.2f} ms")
    print(f"  - Latence Min     : {min_latency:.2f} ms")
    print(f"  - Latence Max     : {max_latency:.2f} ms")
    print("-" * 40)
    print("Analyse : Une latence < 100ms est consideree comme excellente pour une API securisee.")

except Exception as e:
    print(f"ERREUR lors du test : {e}")
    print("Assurez-vous que Docker est lance.")
