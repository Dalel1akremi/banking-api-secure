# 🏦 Banking API Secure

## 📌 Description

Ce projet a pour objectif de concevoir et implémenter une architecture sécurisée pour des API bancaires dans le contexte de l’Open Banking.

Il simule une mini-plateforme bancaire permettant :

* la consultation de comptes
* la gestion des transactions
* l’initiation de paiements

L'accent est mis sur la **sécurisation des API**, la **détection des abus** et la **supervision en temps réel**.

---

## 🎯 Objectifs

* Mettre en place des API bancaires REST
* Appliquer les bonnes pratiques de sécurité (OWASP API Security)
* Implémenter une authentification et autorisation robustes
* Protéger contre les abus (rate limiting, validation)
* Assurer la traçabilité et la supervision des requêtes
* Évaluer l’impact des mécanismes de sécurité sur les performances

---

## ⚙️ Technologies utilisées

* Python / FastAPI
* Uvicorn
* JWT Authentication (à venir)
* OAuth2 / OpenID Connect (Keycloak) *(à venir)*
* API Gateway (NGINX / Kong) *(à venir)*
* Docker & Docker Compose *(à venir)*
* ELK Stack (Monitoring) *(à venir)*

---

## 📂 Structure du projet

```
banking-api-secure/
│
├── main.py
├── models.py
├── database.py
├── routes/
│   ├── accounts.py
│   ├── payments.py
│   └── users.py
└── README.md
```

---

## 🔗 API Endpoints

### 🧾 Accounts

* `GET /accounts` → Liste des comptes
* `GET /accounts/{id}` → Détails d’un compte
* `GET /accounts/{id}/balance` → Solde

### 💳 Payments

* `POST /payments` → Effectuer un paiement

### 👤 Users

* `POST /users` → Créer un utilisateur
* `GET /users/{id}` → Consulter un utilisateur

---

## ▶️ Lancer le projet

### 1. Cloner le projet

```
git clone https://github.com/TON_USERNAME/banking-api-secure.git
cd banking-api-secure
```

### 2. Créer un environnement virtuel

```
python -m venv venv
```

### 3. Activer l’environnement

* Windows :

```
venv\Scripts\activate
```

* Linux/Mac :

```
source venv/bin/activate
```

### 4. Installer les dépendances

```
pip install fastapi uvicorn
```

### 5. Lancer le serveur

```
uvicorn main:app --reload
```

### 6. Accéder à la documentation

* Swagger UI : http://127.0.0.1:8000/docs

---

## 🔐 Sécurité (Roadmap)

* [ ] Authentification JWT
* [ ] Intégration OAuth2 / Keycloak
* [ ] API Gateway (Kong / NGINX)
* [ ] Rate Limiting
* [ ] Protection contre les attaques OWASP
* [ ] Logs centralisés (ELK)
* [ ] Détection des abus

---

## 🧪 Tests

Les tests seront réalisés avec :

* Postman / Insomnia
* Outils de sécurité (OWASP ZAP, Burp Suite)

---

## 📊 Améliorations futures

* Ajout d’une base de données réelle (PostgreSQL / MySQL)
* Mise en place du chiffrement HTTPS / mTLS
* Monitoring avancé et alerting
* Tests de performance

---

## 👨‍💻 Auteur

Projet réalisé dans le cadre d’un mémoire sur la sécurisation des API bancaires.

---

## 📜 Licence

Ce projet est à usage académique.
