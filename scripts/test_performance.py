import requests
import time
import statistics
import urllib3
from concurrent.futures import ThreadPoolExecutor

# Desactiver les avertissements SSL pour les certificats auto-signes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration du test
URL = "https://localhost/api/accounts"
CERTS = ('nginx_certs/client.crt', 'nginx_certs/client.key')
NB_REQUESTS = 100
CONCURRENCY = 35

print(f"--- Benchmark de Performance API Bancaire ---")
print(f"Cible : {URL}")
print(f"Echantillon : {NB_REQUESTS} requetes | mTLS Client Certs : ACTIF")
print("-" * 50)

# 1. Mesure de latence unitaire séquentielle (Concurrence c = 1)
latencies_seq = []
session = requests.Session()
session.cert = CERTS
session.verify = False

for i in range(1, NB_REQUESTS + 1):
    start = time.perf_counter()
    resp = session.get(URL, timeout=5)
    latencies_seq.append((time.perf_counter() - start) * 1000)

avg_lat = statistics.mean(latencies_seq)
med_lat = statistics.median(latencies_seq)
sorted_lat = sorted(latencies_seq)
p95 = sorted_lat[int(len(sorted_lat) * 0.95) - 1]
p99 = sorted_lat[int(len(sorted_lat) * 0.99) - 1]
stdev = statistics.stdev(latencies_seq) if len(latencies_seq) > 1 else 0.0
throughput_seq = 1000.0 / avg_lat

print(f"[1] MESURE SEQUENTIELLE (Concurrence c = 1) :")
print(f"  - Latence Moyenne : {avg_lat:.2f} ms")
print(f"  - Mediane         : {med_lat:.2f} ms")
print(f"  - Percentile 95   : {p95:.2f} ms")
print(f"  - Percentile 99   : {p99:.2f} ms")
print(f"  - Ecart-type (σ)  : {stdev:.2f} ms")
print(f"  - Debit sequentiel: {throughput_seq:.1f} req/s (1 / latence moy.)")
print("-" * 50)

# 2. Mesure de débit saturé sous charge concurrente (Concurrence c = 35)
def send_req(_):
    start = time.perf_counter()
    resp = session.get(URL, timeout=5)
    return time.perf_counter() - start

start_concurrent = time.perf_counter()
with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
    results = list(executor.map(send_req, range(NB_REQUESTS)))
total_time = time.perf_counter() - start_concurrent
throughput_concurrent = NB_REQUESTS / total_time

print(f"[2] MESURE SOUS CHARGE CONCURRENTE (Concurrence c = {CONCURRENCY}) :")
print(f"  - Temps total     : {total_time:.2f} s pour {NB_REQUESTS} requetes")
print(f"  - Debit max sature: {throughput_concurrent:.1f} req/s (Loi de Little N/R)")
print("=" * 50)
