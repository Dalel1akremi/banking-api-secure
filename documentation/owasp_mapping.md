# Cartographie de Sécurité OWASP API Top 10 (2023)

Ce document détaille comment l'architecture "Banking API Secure" répond aux 10 risques de sécurité les plus critiques pour les API, conformément aux recommandations de l'OWASP.

| Risque OWASP API | Statut | Mesures de Mitigation Implémentées |
| :--- | :--- | :--- |
| **API1:2023 - Broken Object Level Authorization (BOLA)** | ✅ Protégé | Chaque accès à un compte (`/accounts/{id}`) vérifie que `owner_id` correspond à l'ID de l'utilisateur extrait du token JWT (`auth.py`). |
| **API2:2023 - Broken Authentication** | ✅ Protégé | Utilisation de **Keycloak** (OIDC/OAuth2) avec signatures RS256. Implémentation d'un **2FA (OTP via email)** pour les actions sensibles. |
| **API3:2023 - Broken Object Property Level Authorization** | ✅ Protégé | Utilisation de modèles Pydantic (`AccountResponse`) qui filtrent strictement les champs retournés (ex: `pin_hash` et `cvv` ne sont jamais exposés). |
| **API4:2023 - Unrestricted Resource Consumption** | ✅ Protégé | **Rate Limiting** implémenté au niveau NGINX (10r/s) et via des décorateurs FastAPI (`@limiter.limit`). |
| **API5:2023 - Broken Function Level Authorization (BFLA)** | ✅ Protégé | Utilisation de **Scopes** Keycloak (`require_scope("write:accounts")`) pour séparer les droits des clients standards des droits d'administration. |
| **API6:2023 - Unrestricted Access to Sensitive Business Flows** | ✅ Protégé | Flux critiques (création de compte, transfert) protégés par une vérification combinée : **Token JWT + PIN + OTP**. |
| **API7:2023 - Server Side Request Forgery (SSRF)** | ✅ Mitigé | L'API ne permet pas de passer des URLs en paramètres pour des requêtes sortantes. Isolation réseau Docker (Zero Trust). |
| **API8:2023 - Security Misconfiguration** | ✅ Protégé | **NGINX Hardening** : Suppression des headers de version (`server_tokens off`), activation du TLS 1.2/1.3 uniquement, et headers de sécurité (CSP, HSTS). |
| **API9:2023 - Improper Inventory Management** | ✅ Géré | Documentation **OpenAPI/Swagger** auto-générée par FastAPI. Versioning via préfixes d'URL (`/api/`). |
| **API10:2023 - Unsafe Consumption of APIs** | ✅ Géré | Validation stricte des types de données via Pydantic pour toutes les communications inter-services. |

---

## 🛠️ Validation par Tests
- **Tests d'Abus :** Le script `test_ratelimit.py` valide la protection contre le Brute Force (API2 & API4).
- **Tests d'Identité :** La validation mTLS sur NGINX assure qu'aucun partenaire non autorisé ne peut même atteindre l'API (Zero Trust).
- **Audit Logs :** Chaque action est logguée dans `security_audit.log` et streamée vers **Elasticsearch** pour une détection d'anomalies a posteriori.

---

> [!IMPORTANT]
> Ce tableau sert de base pour la rédaction de votre chapitre sur la "Validation de la Sécurité" dans votre mémoire. Il prouve que la conception suit une approche "Security by Design".
