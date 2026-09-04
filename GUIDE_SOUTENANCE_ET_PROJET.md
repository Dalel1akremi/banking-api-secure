# 🎓 GUIDE COMPLET DE RÉVISION & DE SOUTENANCE TECHNIQUE
## Projet : Architecture Zero Trust et Supervision SIEM/SOAR pour la Sécurisation des API Bancaires
**Auteure :** Dalel AKREMI | **Encadrant :** Dr. Akram BELAZI | **Formation :** MPSSI — ISIMG

---

# 📑 TABLE DES MATIÈRES
1. [Le Pitch en 1 minute (Introduction)](#1-le-pitch-en-1-minute)
2. [L'Histoire du Projet expliquée simplement](#2-lhistoire-du-projet-expliquée-simplement)
3. [Les 3 Gardiens du Système (Fonctionnement)](#3-les-3-gardiens-du-système)
4. [La Segmentation Réseau (Les 4 Réseaux Docker)](#4-la-segmentation-réseau)
5. [Le Système d'Alarme Intelligent (La Défense Active SOAR)](#5-le-système-dalarme-intelligent)
6. [Les Chiffres Clés à Retenir par Cœur](#6-les-chiffres-clés-à-retenir-par-cœur)
7. [Questions Pièges du Jury & Réponses Types](#7-questions-pièges-du-jury--réponses-types)
8. [Plan de Présentation pour le Jour J (Diapo par Diapo)](#8-plan-de-présentation-pour-le-jour-j)
9. [Glossaire des Termes & Acronymes Clés](#9-glossaire-des-termes--acronymes-clés)

---

# 1. LE PITCH EN 1 MINUTE

> *"Bonjour à tous. Notre projet conçoit et valide une architecture de sécurité **Zero Trust** pour les API bancaires ouvertes dans le cadre de l'**Open Banking** et de la directive européenne **DSP2**.*
>
> *Face à l'effacement des frontières classiques des réseaux bancaires, nous combinons une barrière cryptographique au niveau transport (**mTLS**), une gestion stricte des identités et des consentements (**Keycloak / OAuth2 PKCE / JWT RS256**), et un automate de défense active (**SOAR / pile ELK**) capable d'isoler une adresse IP hostile en moins de 30 secondes grâce à un score dynamique de menace à décroissance temporelle ($T_{decay}$).*
>
> *Les tests ont prouvé l'efficacité de notre solution : **0 vulnérabilité critique** détectée sous OWASP ZAP et une latence globale de **72,3 ms**, garantissant le principe de parité de service DSP2 (RTS UE 2018/389 Art. 32/36) et restant très largement sous les seuils de recommandation de l'industrie Open Banking (200 ms)."*

---

# 2. L'HISTOIRE DU PROJET EXPLIQUÉE SIMPLEMENT

### 🏦 La Banque d'Hier (Le modèle château-fort) :
- Avant, une banque était un réseau fermé.
- Pour consulter vos comptes, vous alliez au guichet ou sur le portail officiel de la banque.
- Les pare-feux suffisaient car personne de l'extérieur n'avait d'accès direct au système interne.

### 📱 La Banque d'Aujourd'hui (L'Open Banking & Directive DSP2) :
- La réglementation européenne **DSP2** (Directive sur les Services de Paiement 2) oblige les banques à **ouvrir leurs portes**.
- Des applications partenaires tierces agréées (**TPP** : *Third Party Providers*, comme des agrégateurs de comptes ou des applications de budget) doivent pouvoir se connecter à la banque avec l'accord du client.
- Pour cela, la banque met à disposition des **API** (*Application Programming Interfaces*).

### ⚠️ Le Grand Problème :
- Dès qu'une banque ouvre des API sur Internet, **les cybercriminels essaient d'entrer par les mêmes portes** (attaques par force brute, vol de comptes, usurpation d'identité, déni de service).
- **Le Défi :** Comment ouvrir les portes aux partenaires légitimes tout en bloquant les attaquants à coup sûr ?
- **La Solution :** Le paradigme **Zero Trust** (*"Ne jamais faire confiance, toujours vérifier"*).

---

# 3. LES 3 GARDIENS DU SYSTÈME

Imaginez votre système informatique comme un bâtiment bancaire protégé par 3 niveaux successifs de contrôle :

```
       [ Client Web / Mobile ou Partenaire TPP ]
                           │
                           ▼ (HTTPS:443 / TLS 1.3 + mTLS)
       ┌────────────────────────────────────────┐
       │ 1. LE VIGILE À L'ENTRÉE : NGINX (mTLS) │
       └────────────────────────────────────────┘
                           │ (Routage sécurisé)
                           ▼
       ┌────────────────────────────────────────┐
       │ 2. LE GUICHET D'IDENTITÉ : Keycloak    │
       │    (Authentification 2FA & Consentement)│
       └────────────────────────────────────────┘
                           │ (Jeton d'accès JWT RS256)
                           ▼
       ┌────────────────────────────────────────┐
       │ 3. LA SALLE DU COFFRE : FastAPI        │
       │    (Traitement des virements & comptes) │
       └────────────────────────────────────────┘
```

### 🛡️ Gardien 1 : Le Vigile à la Porte — NGINX (Passerelle mTLS)
- C'est le point d'entrée unique sur les ports 80 (redirection HTTPS) et 443.
- **Le mTLS (Mutual TLS) :** Contrairement au HTTPS standard où seul le serveur prouve qui il est, le mTLS exige que l'application partenaire (TPP) présente **son propre certificat numérique privé** signé par la banque.
- *Si un pirate tente de se connecter sans certificat valide $\rightarrow$ NGINX le rejette immédiatement avec un code **400 Bad Request** sans jamais déranger le reste du système.*
- NGINX applique aussi la limitation de débit (*Rate Limiting* : 10 requêtes/seconde).

### 🔑 Gardien 2 : Le Guichet d'Identité — Keycloak (Serveur IAM)
- Il s'occupe exclusivement de la gestion des utilisateurs, des rôles et des autorisations.
- **Double Facteur (2FA / SCA) :** Il valide le mot de passe (1er facteur) puis demande un code éphémère à 6 chiffres (2ème facteur) :
  - *Parcours nominal :* Code **OTP envoyé par courriel** via SMTP.
  - *Parcours alternatif :* Code **TOTP généré par une application** (Google Authenticator / FreeOTP).
- **Émission du Token JWT :** Une fois l'identité confirmée, Keycloak délivre un badge numérique (**JWT**) signé cryptographiquement avec l'algorithme asymétrique **RS256** (valable 15 minutes).

### 💼 Gardien 3 : La Salle du Coffre — FastAPI (Backend Bancaire)
- Développé en Python asynchrone ultra-rapide.
- Il reçoit les requêtes métiers (virements, soldes, budgets, prêts).
- Il vérifie la signature du jeton JWT de manière totalement autonome grâce à la clé publique de Keycloak, **sans avoir besoin de réinterroger la base d'identité à chaque requête** (*validation sans état / stateless*).
- Il enregistre les données financières dans **MongoDB** (avec typage strict `Decimal` pour éviter les erreurs d'arrondi) et ne stocke **aucun CVV ni mot de passe en clair**.

---

# 4. LA SEGMENTATION RÉSEAU (LES 4 RÉSEAUX DOCKER)

Pour appliquer le Zero Trust, les conteneurs Docker ne sont pas mélangés dans un seul réseau : ils sont cloisonnés en **4 réseaux étanches** :

| Réseau Docker | Rôle | Composants hébergés | Niveau d'exposition |
|---|---|---|---|
| **`frontend_tier`** | DMZ (Zone frontière) | Passerelle **NGINX** | Seul réseau exposé à l'extérieur (Ports 80/443) |
| **`backend_tier`** | Zone applicative interne | **FastAPI** (8000), **Flask** (5000), **Keycloak** (8080), **Threat Monitor**, **SecurityState**, **Redis** (6379) | Totalement privé, accessible uniquement via NGINX |
| **`data_tier`** | Cœur de persistance | **MongoDB** (27017 pour l'API), **PostgreSQL** (5432 pour Keycloak) | `internal: true` (aucun accès réseau externe possible) |
| **`monitoring_tier`** | Supervision de sécurité | **Filebeat** (5044), **Logstash** (5044), **Elasticsearch** (9200), **Kibana** (5601) | Réseau dédié à la collecte et l'analyse des logs |

---

# 5. LE SYSTÈME D'ALARME INTELLIGENT (LA DÉFENSE ACTIVE SOAR)

### ❓ Pourquoi les SIEM traditionnels (ELK seul) ne suffisent pas ?
Un SIEM classique collecte des millions de lignes de logs et affiche de jolis tableaux de bord. Mais si un pirate attaque à 3 heures du matin avec un script automatique, **le pirate aura fini son attaque bien avant qu'un humain ne voie l'alerte le lendemain matin**.

### ⚡ Notre Solution : Le SOAR (Sécurité Réactive Automatisée)
Nous avons créé un automate qui analyse les erreurs HTTP en direct et calcule un **score de menace dynamique** :

$$T_{decay}(x, t) = T(x, t_{last}) \cdot e^{-\lambda (t - t_{last})} + w(e_{current})$$
avec $\lambda = \frac{\ln(2)}{120} \approx 0{,}005776\text{ s}^{-1}$ (demi-vie de 120 s).

### 🧮 Démonstration Mathématique Pas à Pas (Exemple d'une attaque brute force) :
Pour des requêtes d'échec d'authentification ($w = 1{,}0$) espacées de $\Delta t = 5\text{ secondes}$ ($e^{-\lambda \times 5} \approx 0{,}9715$) :
- **Requête 1 ($t = 0\text{ s}$) :** $T_1 = 1{,}000$
- **Requête 2 ($t = 5\text{ s}$) :** $T_2 = 1{,}000 \cdot e^{-0{,}0289} + 1{,}0 = 1{,}972$
- **Requête 3 ($t = 10\text{ s}$) :** $T_3 = 1{,}972 \cdot e^{-0{,}0289} + 1{,}0 = 2{,}915$ *(seuil non atteint)*
- **Requête 4 ($t = 15\text{ s}$) :** $T_4 = 2{,}915 \cdot e^{-0{,}0289} + 1{,}0 = 3{,}832 \ge 3{,}0$ $\implies$ **Déclenchement immédiat de l'alerte au 4\textsuperscript{ème} échec en 15 secondes !**

### 📊 Validation Statistique sur Corpus de Test ($N = 1000$ sessions) :
Sur un jeu d'évaluation de 1000 sessions (800 légitimes et 200 attaques simulées) :
- **Vrais Positifs ($\text{TP}$) :** $198$ (attaques correctement bloquées)
- **Faux Positifs ($\text{FP}$) :** $4$ (utilisateurs légitimes s'étant trompés 4 fois de suite en 15 s, sauvés par le minuteur de 30 s)
- **Vrais Négatifs ($\text{TN}$) :** $796$ (trafic légitime accepté)
- **Faux Négatifs ($\text{FN}$) :** $2$ (sondes très lentes espacées de $> 4$ min)
- **Exactitude ($\text{Accuracy}$) :** $\mathbf{99{,}4\,\%}$
- **Précision :** $\mathbf{98{,}02\,\%}$
- **Rappel / Sensibilité ($\text{Recall}$) :** $\mathbf{99{,}00\,\%}$
- **F1-Score :** $\mathbf{98{,}51\,\%}$

---

# 6. LES CHIFFRES CLÉS À RETENIR PAR CŒUR

| Métrique | Valeur de votre projet | Norme / Référence légale | Ce que cela prouve |
|---|:---:|---|---|
| **Latence totale de l'API** | **`72,3 ms`** | Parité DSP2 RTS (Art. 32/36) & Benchmark Open Banking (200 ms) | L'API est ultra-rapide et respecte l'équivalence de service légale. |
| **Débit séquentiel ($c=1$)** | **`13,8 req/s`** | $1 / \text{latence}$ ($1 / 0{,}0723\text{ s}$) | Vitesse unitaire d'un client unique qui attend chaque réponse. |
| **Débit saturé ($c=35$ clients)** | **`465 req/s`** | Loi de Little ($X = N / R$) | Capacité maximale de l'API sous charge concurrente. |
| **Surcoût de la sécurité** | `34,1 ms` | --- | L'ajout de mTLS + JWT + SIEM n'alourdit pas les transactions. |
| **Surcoût du Threat Monitor** | **`4,2 ms`** | --- | L'analyse de menace en temps réel est quasi-invisible pour l'utilisateur. |
| **F1-Score Détection SOAR** | **`98,51 %`** | Matrice de confusion ($N=1000$) | Détection hautement fiable avec quasi-zéro faux négatif. |
| **Délai de réaction SOAR** | **`< 1 seconde`** | --- | Détection instantanée dès franchissement du seuil $S=3{,}0$. |
| **Délai de blocage total** | **`31 secondes`** | --- | 1 s de calcul + 30 s de minuteur de sécurité. |
| **Audit OWASP ZAP (DAST)** | **`0 High, 0 Medium`** | Référentiel OWASP API Top 10 | Aucune faille d'injection, BOLA ou élévation de privilège. |

---

# 7. QUESTIONS PIÈGES DU JURY & RÉPONSES TYPES

### ❓ Question 1 : *"Pourquoi ne pas utiliser un simple WAF (Web Application Firewall) ?"*
> **Votre réponse :** *"Un WAF classique fonctionne par signatures statiques (expressions régulières). Il est très efficace pour bloquer une injection SQL évidente, mais il est incapable de détecter un abus de logique métier comme une faille **BOLA** (où un utilisateur connecté légitime modifie l'identifiant d'un compte dans l'URL pour voir celui de son voisin). Notre approche combine la validation applicative fine des droits dans FastAPI et un moteur de corrélation comportementale SOAR qui suit l'historique des erreurs d'une IP dans le temps."*

### ❓ Question 2 : *"Pourquoi utiliser Keycloak ET FastAPI plutôt que de tout coder en Python ?"*
> **Votre réponse :** *"C'est le principe fondamental de **séparation des responsabilités** imposé par les normes bancaires (FAPI 1.0) et le Zero Trust. Keycloak est un serveur d'identité certifié et durci qui gère le hachage des mots de passe, les cycles de vie des sessions et la révocation des tokens. FastAPI reste purement dédié au métier bancaire et valide les jetons JWT de manière autonome (stateless) via la clé publique de Keycloak, sans jamais stocker d'identifiants sensibles."*

### ❓ Question 3 : *"Un pirate peut-il tricher sur son IP avec l'en-tête `X-Forwarded-For` ?"*
> **Votre réponse :** *"Non, car nous appliquons le principe Zero Trust : nous ne faisons jamais confiance aux en-têtes envoyés par le client. À l'entrée DMZ, NGINX écrase systématiquement la variable `X-Real-IP` avec l'adresse IP réseau réelle issue de la socket TCP (`$remote_addr`). C'est cette valeur vérifiée qui est utilisée par le middleware FastAPI et le Threat Monitor."*

### ❓ Question 4 : *"Pourquoi MongoDB pour une banque alors qu'on utilise souvent du SQL ?"*
> **Votre réponse :** *"Dans notre architecture, nous avons une séparation hybride : PostgreSQL est utilisé pour Keycloak (ACID relationnel pour l'IAM), et MongoDB pour les données de l'API. Dans MongoDB, nous garantissons l'intégrité grâce au typage strict `Decimal` via Pydantic (aucun arrondi flottant), à l'exclusion du stockage de CVV (conformité PCI-DSS), et aux transactions multi-documents ACID de MongoDB. En environnement industriel de production, ce cœur métier peut être branché sur un SGBD relationnel classique ou distribué."*

### ❓ Question 5 : *"Un code HMAC ou un fichier append-only garantit-il la non-répudiation des logs ?"*
> **Votre réponse :** *"Non, et c'est un piège cryptographique classique ! Le mode ajout seul (`append-only`) évite seulement les écrasements accidentels, et un code **HMAC est symétrique** : comme la clé secrète est connue du serveur, un administrateur ou un attaquant ayant compromis la machine pourrait recalculer des HMAC valides pour des logs falsifiés.*
>
> *Pour obtenir une vraie **non-répudiation juridique** (conforme PCI-DSS et ISO 27001), il faut la combinaison de 4 piliers :*
> 1. *Un **chaînage cryptographique unidirectionnel (Merkle Hash Chain)** : chaque ligne intègre le hachage SHA-256 de la ligne précédente.*
> 2. *Une **signature numérique asymétrique (ECDSA / RSA-PSS)** dont la clé privée est scellée dans un boîtier matériel durci (**HSM - Hardware Security Module**).*
> 3. *Un **horodatage qualifié par un tiers de confiance (TSA certifiée RFC 3161 / eIDAS)**.*
> 4. *Un **stockage physique immuable WORM** (Write Once, Read Many / AWS S3 Object Lock en mode Compliance) interdisant toute suppression, même par le compte Root."*

### ❓ Question 6 : *"Quelles sont les 3 différences entre votre prototype et la cible de production ?"*
> **Votre réponse :**
> 1. *Le registre des adresses bloquées (`SecurityState`) sera stocké dans un cluster **Redis partagé** au lieu de la mémoire vive d'un nœud unique.*
> 2. *Le blocage IP sera effectué au niveau du noyau Linux via des règles de filtrage **eBPF / iptables** ou directement dans NGINX pour ne pas consommer de CPU Python.*
> 3. *Le déploiement basculera de Docker Compose vers un cluster **Kubernetes multi-nœuds** avec haute disponibilité.*

---

# 8. PLAN DE PRÉSENTATION POUR LE JOUR J

Voici la structure idéale pour vos diapositives (durée conseillée : 15 à 20 minutes) :

| Diapo | Titre de la Diapositive | Ce qu'il faut dire |
|:---:|---|---|
| **1** | **Titre & Présentation** | Présentez-vous, remerciez l'encadrant et annoncez le sujet. |
| **2** | **Contexte : L'Open Banking & DSP2** | Expliquez l'ouverture obligatoire des banques vers les TPP et les risques de cyberattaque. |
| **3** | **Problématique & Objectifs** | Comment ouvrir les API bancaires sans créer de failles ? Présentation de l'approche Zero Trust. |
| **4** | **Architecture Globale (Figure 2)** | Montrez les 4 réseaux Docker : DMZ NGINX, Backend (FastAPI, Flask, Keycloak), Data, Monitoring ELK. |
| **5** | **La Barrière mTLS & OAuth2 (Figure 3)** | Expliquez que les partenaires TPP doivent obligatoirement fournir un certificat client X.509. |
| **6** | **L'Authentification Forte 2FA (Figure 5)** | Présentez les 2 parcours : OTP par email (nominal) et TOTP sur smartphone (alternatif). |
| **7** | **Modèle de Données Sécurisé (Figure 6)** | Précisez le typage `Decimal`, le hachage bcrypt/argon2 et l'absence totale de CVV stocké. |
| **8** | **L'Innovation : Le Moteur SOAR** | Présentez la formule du score $T_{decay}$, l'atténuation temporelle et le seuil $S=3{,}0$. |
| **9** | **Validation : Audit OWASP ZAP** | Montrez le résultat : 0 vulnérabilité critique (High/Medium). |
| **10** | **Banc d'Essai de Performance** | Présentez le tableau : 72,3 ms de latence moyenne (très loin sous la barre des 200 ms du SLA). |
| **11** | **Démonstration / Captures d'Écran** | Montrez brièvement le Dashboard Kibana et l'écran de blocage d'IP en temps réel. |
| **12** | **Conclusion & Perspectives** | Résumez le succès du prototype et citez les perspectives industrielles (Redis, eBPF, Kubernetes). |

---

# 9. GLOSSAIRE DES TERMES & ACRONYMES CLÉS

- **API (*Application Programming Interface*) :** Interface logicielle permettant à deux applications de communiquer entre elles.
- **mTLS (*Mutual Transport Layer Security*) :** Protocole où le client et le serveur vérifient mutuellement leurs certificats cryptographiques.
- **Zero Trust :** Philosophie de sécurité où aucun utilisateur ni système interne n'est considéré comme digne de confiance par défaut.
- **DSP2 / PSD2 :** Directive européenne imposant l'ouverture des données bancaires aux prestataires tiers agréés.
- **TPP (*Third Party Provider*) :** Application tierce autorisée à interagir avec une banque (ex : agrégateur de comptes).
- **JWT (*JSON Web Token*) :** Format compact de jeton d'accès signé numériquement (ici en RS256).
- **2FA / MFA :** Authentification à double facteur combinant ce que vous savez (mot de passe) et ce que vous possédez (smartphone / email).
- **OTP (*One-Time Password*) :** Mot de passe à usage unique reçu par courriel ou SMS.
- **TOTP (*Time-based One-Time Password*) :** Code temporaire à 6 chiffres renouvelé toutes les 30 secondes (RFC 6238).
- **SIEM (*Security Information and Event Management*) :** Plateforme de collecte et d'analyse centralisée des journaux de sécurité (ici la pile ELK : Elasticsearch, Logstash, Kibana).
- **SOAR (*Security Orchestration, Automation and Response*) :** Automate capable de réagir et de bloquer une menace sans attendre une intervention humaine.
- **DAST (*Dynamic Application Security Testing*) :** Test de sécurité en boîte noire simulant des attaques réelles sur une application en cours d'exécution (ex : OWASP ZAP).
- **BOLA (*Broken Object Level Authorization*) :** Faille permettant à un utilisateur d'accéder aux données d'un autre en changeant un simple identifiant dans la requête.
- **SLA (*Service Level Agreement*) :** Accord de niveau de service garantissant des temps de réponse minimaux (seuil de 200 ms en DSP2).

---
*Ce document récapitulatif est votre allié de révision. Bon courage pour votre soutenance, vous maîtrisez parfaitement votre sujet !* 🚀
