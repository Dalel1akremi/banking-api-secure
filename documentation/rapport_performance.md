# ⚡ Rapport de Performance et Latence

Ce document évalue l'impact des mécanismes de sécurité (mTLS, NGINX Proxy, Authentification) sur la réactivité de l'API bancaire.

## 1. Méthodologie du Test
*   **Outil :** Script Python personnalisé (`scripts/test_performance.py`).
*   **Conditions :** 50 requêtes successives via la Gateway NGINX.
*   **Couches testées :** 
    1.  Négociation SSL/TLS (v1.3).
    2.  Vérification de certificat client (mTLS).
    3.  Routage NGINX.
    4.  Temps de réponse du Backend (FastAPI).

## 2. Résultats Obtenus (Moyenne réelle)
| Mesure | Valeur Obtenue | Statut |
| :--- | :--- | :--- |
| **Latence Moyenne** | **146.39 ms** | 🟢 Très Satisfaisant |
| **Latence Minimale** | **122.19 ms** | 🟢 Réactif |
| **Latence Maximale** | **262.30 ms** | 🟢 Stable |

## 3. Analyse de l'Impact
L'ajout du **mTLS** et de la **Gateway** (couches de sécurité critique) maintient un temps de réponse sous la barre des 200ms sur une machine de développement.

**Conclusion :** L'architecture offre un compromis idéal entre **sécurité maximale** (Open Banking) et **expérience utilisateur fluide**.

---
*Note : Pour mettre à jour ces chiffres, lancez `python scripts/test_performance.py`.*
