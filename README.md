# 🏦 Banking API Secure

## 📌 Description

Ce projet implémente une architecture hautement sécurisée pour des API bancaires dans le contexte de l’Open Banking. Il sert de démonstrateur pour un mémoire sur la cybersécurité bancaire.

L'accent est mis sur la **sécurisation multicouche**, la **détection des menaces par IA** et la **supervision SIEM**.

---

## 🎯 Objectifs Réalisés

*   **Zero Trust Architecture** : Segmentation réseau Docker et mTLS.
*   **Authentification Robuste** : OAuth2 / OpenID Connect via Keycloak + 2FA (OTP).
*   **Contrôle d'Accès** : Gestion fine des Scopes (Lecture/Écriture/Admin).
*   **Protection API** : Rate limiting, masquage de données, et validation stricte.
*   **Observabilité SIEM** : Centralisation des logs via Stack ELK (Kibana).
*   **IA de Détection** : Analyse comportementale des logs pour identifier les abus.

---

## 🛡️ Documentation de Sécurité

Pour votre mémoire, consultez les rapports de conformité suivants :

1.  **[Mapping OWASP API Top 10](owasp_mapping.md)** : Comment l'API répond aux risques critiques.
2.  **[Analyse de Conformité](analysis_results.md)** : État actuel vs Cahier des charges.
3.  **[Rapport OWASP ZAP](documentation/zap_report.html)** : Rapport de scan de vulnérabilités (à générer via le script).

---

## ⚙️ Technologies & Infrastructure

*   **Backend** : Python / FastAPI (Validation Pydantic)
*   **Gateway** : NGINX (mTLS, Rate Limit, Security Headers)
*   **Identité** : Keycloak (RS256 JWT, OIDC)
*   **Monitoring** : Stack ELK (Elasticsearch, Logstash, Kibana, Filebeat)
*   **Base de données** : MongoDB (Comptes) & PostgreSQL (Keycloak)
*   **Conteneurisation** : Docker & Docker Compose

---

## ▶️ Lancer le projet

### 1. Démarrer l'infrastructure complète
```bash
docker-compose up -d
```

### 2. Lancer un Scan de Sécurité (OWASP ZAP)
Pour générer le rapport requis par le cahier des charges :
```powershell
.\scripts\run_zap_scan.ps1
```

---

## 🧪 Tests de Sécurité Inclus

*   `test_ratelimit.py` : Simulation d'attaque Brute Force.
*   `test.js` : Tests de charge et validation mTLS.

---

## 📊 Supervision

Accédez au dashboard SIEM (Kibana) : [http://localhost:5601](http://localhost:5601)
*   Visualisation des logs NGINX en temps réel.
*   Alertes sur les tentatives d'intrusion.

---

## 👨‍💻 Auteur

Projet réalisé dans le cadre d’un mémoire sur la sécurisation des API bancaires.

---

## 📜 Licence

Ce projet est à usage académique.
