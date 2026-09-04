from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from app.security.auth import verify_token
from app.db import support_collection, users_collection
import datetime
import os
from dotenv import load_dotenv

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

gemini_client = None
if GEMINI_API_KEY:
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_client = genai
    except Exception:
        gemini_client = None

router = APIRouter(prefix="/support", tags=["Support"])

# ==============================
# 📦 MODELS
# ==============================

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=500)

class SupportMessageRequest(BaseModel):
    subject: str = Field(..., min_length=2, max_length=100)
    category: str = Field(..., pattern="^(Assurance|Credit|Incident Carte|Placement|Autre)$")
    content: str = Field(..., min_length=10, max_length=2000)

# ==============================
# 🤖 CHATBOT LOGIC (Assistant Intelligent)
# ==============================

import re
import unicodedata

def normalize_text(text: str):
    """
    Normalise le texte : suppression des accents, conversion en minuscules,
    remplacement des caractères spéciaux par des espaces, et réduction des lettres
    répétées consécutives (ex: 'virrement' -> 'virement', 'khallless' -> 'khales').
    """
    text_no_accents = unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('utf-8').lower()
    cleaned = re.sub(r'[^a-z0-9\s]', ' ', text_no_accents)
    collapsed = re.sub(r'(.)\1+', r'\1', cleaned)
    return cleaned, collapsed

def has_match(raw: str, coll: str, keywords: list) -> bool:
    """Vérifie si l'un des mots-clés correspond au texte brut ou au texte sans répétitions."""
    for kw in keywords:
        if kw in raw or kw in coll:
            return True
        if re.search(r'\b' + re.escape(kw), raw) or re.search(r'\b' + re.escape(kw), coll):
            return True
    return False

@router.post("/chat")
def chatbot_responder(data: ChatRequest, user=Depends(verify_token)):
    raw, coll = normalize_text(data.message)
    
    # 1. Salutations & Accueil
    if has_match(raw, coll, ["bonjour", "salut", "hello", "coucou", "ahla", "salam", "aslema", "marhba", "sbah", "sbe7", "bonsoir"]):
        reply = (
            "Bonjour ! 👋 Je suis l'assistant virtuel d'API Bank.\n\n"
            "Je suis là pour vous guider pas à pas dans toutes les fonctionnalités de l'application :\n"
            "• 💸 Effectuer un virement ou transfert\n"
            "• 💳 Gérer, activer ou bloquer votre carte bancaire\n"
            "• 💡 Payer vos factures (STEG, SONEDE, Télécom)\n"
            "• 🧮 Simuler un crédit et calculer vos mensualités\n"
            "• 📊 Suivre et ajuster votre budget mensuel\n"
            "• 📍 Trouver nos agences et distributeurs DAB 24/7\n"
            "• 📄 Télécharger votre RIB officiel (PDF)\n\n"
            "Que souhaitez-vous faire aujourd'hui ?"
        )

    # 2. Identité & Rôle
    elif has_match(raw, coll, ["qui es tu", "qui est tu", "tu es qui", "chkoun enta", "c est quoi ton role", "qui es-tu", "t es qui", "chnowa taamel", "chnoua te5dem"]):
        reply = (
            "Je suis l'assistant virtuel intelligent d'API Bank 🤖.\n"
            "Mon rôle est de vous guider et vous expliquer comment utiliser toutes les fonctionnalités de votre banque en ligne 24h/24.\n\n"
            "Si vous rencontrez un problème particulier ou une réclamation, vous pouvez également vous rendre dans la Messagerie (menu Support) pour qu'un conseiller ou administrateur vous prenne en charge."
        )

    # 3. Virements & Transferts d'argent (tolérance aux fautes : virement, virrement, virment, nbaath, etc.)
    elif has_match(raw, coll, ["virement", "virrement", "virment", "virr", "virm", "transfert", "transfer", "transfere", "transfeer", "transfr", "envoyer argent", "nbaath", "baath", "chaye3", "beneficiaire", "destinataire", "mandat", "vire"]):
        reply = (
            "💸 **Comment effectuer un virement bancaire :**\n\n"
            "1. Rendez-vous sur votre **Tableau de Bord** (Dashboard) et cliquez sur votre compte.\n"
            "2. Cliquez sur l'onglet **« Virements »** (ou sur le bouton **« Effectuer un virement »**).\n"
            "3. Choisissez le compte destinataire (sélectionnez un bénéficiaire enregistré ou saisissez le RIB / numéro de compte).\n"
            "4. Indiquez le **montant** à transférer et le motif (ex: loyer, achat).\n"
            "5. Saisissez votre **code PIN** à 4 chiffres (et votre code OTP si demandé pour la sécurité Zero Trust).\n"
            "6. Cliquez sur **« Envoyer le virement »** : les fonds sont transférés instantanément et votre reçu est disponible immédiatement !"
        )

    # 4. Cartes Bancaires (Blocage, Déblocage, Perte, Vol, PIN, CVV)
    elif has_match(raw, coll, ["bloquer", "debloquer", "opposition", "perdu", "vol", "dha3et", "dha3t", "ser9a", "tser9et", "desactiver", "activer carte", "perte carte", "carte bancaire", "ma carte", "bloque", "debloque", "code pin", "changer pin", "pin oublie", "cvv", "cryptogramme"]):
        reply = (
            "💳 **Comment gérer, bloquer ou débloquer votre carte bancaire :**\n\n"
            "• **Bloquer / Débloquer en un clic :**\n"
            "1. Dans le menu latéral de gauche, cliquez sur **« 💳 Ma Carte »**.\n"
            "2. Repérez l'interrupteur **« État de la carte »**.\n"
            "3. Basculez-le sur **Désactivée** : votre carte est bloquée instantanément en cas de perte, de vol ou de doute.\n"
            "4. Si vous la retrouvez, il vous suffit de recliquer sur ce même interrupteur pour la réactiver immédiatement !\n\n"
            "• **Code PIN & Sécurité :**\n"
            "Dans ce même espace, vous pouvez consulter vos informations sécurisées et demander la réinitialisation de votre code PIN à 4 chiffres."
        )

    # 5. Plafonds de Carte
    elif has_match(raw, coll, ["plafond", "plafonds", "limite carte", "limite de paiement", "augmenter plafond", "modifier plafond", "limite retrait"]):
        reply = (
            "💳 **Comment consulter et modifier vos plafonds de carte :**\n\n"
            "1. Accédez à la rubrique **« 💳 Ma Carte »** depuis le menu de navigation.\n"
            "2. Vous visualiserez vos plafonds hebdomadaires de paiement par carte et de retrait DAB.\n"
            "3. Si vous avez souscrit à l'**Offre Prime**, vous pouvez ajuster et personnaliser vos plafonds en temps réel selon vos besoins !"
        )

    # 6. Factures & Recharges téléphoniques (STEG, SONEDE, TT, etc.)
    elif has_match(raw, coll, ["facture", "factur", "steg", "sonede", "telecom", "tunisie telecom", "orange", "ooredoo", "recharge", "khallas", "khalas", "payer", "electricite", "gaz", "dho", "mae", "internet", "factures"]):
        reply = (
            "💡 **Comment payer vos factures en ligne :**\n\n"
            "1. Dans le menu latéral de gauche, cliquez sur **« 💡 Factures »**.\n"
            "2. Sélectionnez votre organisme :\n"
            "   • **STEG** (Électricité et Gaz)\n"
            "   • **SONEDE** (Distribution de l'eau)\n"
            "   • **Tunisie Telecom / Orange / Ooredoo** (Internet et Téléphonie)\n"
            "3. Renseignez la référence de votre facture et le montant.\n"
            "4. Choisissez le compte bancaire à débiter.\n"
            "5. Validez avec votre code PIN bancaire.\n"
            "6. Le paiement est validé immédiatement : le montant est débité de votre compte et automatiquement déduit de votre **Budget Mensuel** dans la catégorie Factures !"
        )

    # 7. Simulation de Crédit & Prêts
    elif has_match(raw, coll, ["credit", "pret", "emprunt", "simulation", "simuler", "mensualite", "taux", "taslif", "9ardh", "qardh", "salaf", "kredy", "amortissement", "tmm"]):
        reply = (
            "🧮 **Comment simuler un crédit bancaire :**\n\n"
            "1. Cliquez sur le menu **« 🧮 Simulation de Crédit »** (ou sur l'onglet 'Crédit' depuis la page de votre compte).\n"
            "2. Renseignez les paramètres de votre projet :\n"
            "   • **Montant souhaité** (ex: 10 000 DT)\n"
            "   • **Durée** en mois (ex: 36 ou 60 mois)\n"
            "   • **Taux annuel** (TMM + marge)\n"
            "   • Vos **revenus mensuels** (pour évaluer votre capacité d'emprunt)\n"
            "3. Cliquez sur **« Calculer la simulation »**.\n"
            "4. L'application calcule immédiatement votre **mensualité exacte**, le coût total des intérêts et vérifie automatiquement si votre taux d'endettement respecte la règle prudentielle (maximum 33% à 40%)."
        )

    # 8. Solde, Historique & Relevé de compte
    elif has_match(raw, coll, ["solde", "sold", "balance", "flous", "flousi", "argent", "combien j ai", "kadeh aand", "9adech", "chhal", "avoir", "historique", "transaction", "mouvements", "releve", "extrait"]):
        reply = (
            "💰 **Comment consulter votre solde et vos opérations :**\n\n"
            "1. Rendez-vous sur votre **Tableau de Bord** (Dashboard).\n"
            "2. Vous y trouverez le solde en temps réel de chacun de vos comptes (Courant, Épargne).\n"
            "3. Cliquez sur un compte pour afficher l'historique complet de toutes vos transactions (dépôts, retraits, virements, factures).\n"
            "4. Vous pouvez également consulter le **« Journal d'activité »** (menu 🛡️) pour un audit complet de toutes vos actions récentes."
        )

    # 9. Téléchargement de RIB / IBAN officiel
    elif has_match(raw, coll, ["rib", "iban", "releve d identite", "telecharger rib", "attestation rib", "mon rib"]):
        reply = (
            "📄 **Comment télécharger votre RIB officiel en PDF :**\n\n"
            "1. Rendez-vous sur votre **Tableau de Bord**.\n"
            "2. Cliquez sur votre compte bancaire pour ouvrir ses détails.\n"
            "3. Cliquez sur le bouton bleu **« 📄 Télécharger RIB (PDF) »** situé sous les informations du compte.\n"
            "4. Votre Relevé d'Identité Bancaire officiel sécurisé (avec IBAN, code agence et QR code de vérification) sera instantanément généré et téléchargé !"
        )

    # 10. Budget Mensuel & Alertes Dépenses
    elif has_match(raw, coll, ["budget", "masrouf", "depense", "depenses", "epargne", "tirelire", "plafond budget", "categorie", "economie"]):
        reply = (
            "📊 **Comment gérer votre Budget Mensuel :**\n\n"
            "1. Cliquez sur **« 📊 Budget Mensuel »** dans le menu latéral.\n"
            "2. Sélectionnez le compte bancaire que vous souhaitez suivre.\n"
            "3. Définissez vos plafonds de dépenses par catégorie (Alimentation, Factures, Logement, Transport, Loisirs...).\n"
            "4. À chaque dépense ou paiement de facture, la jauge s'actualise en direct avec des alertes automatiques si vous approchez de 80% ou dépassez votre limite !"
        )

    # 11. Agences & Distributeurs DAB / ATM
    elif has_match(raw, coll, ["agence", "agences", "dab", "atm", "distributeur", "gab", "guichet", "adresse", "win mawjoud", "localisation", "trouver agence", "horaire", "itineraire"]):
        reply = (
            "📍 **Comment localiser une agence ou un distributeur DAB 24/7 :**\n\n"
            "1. Cliquez sur le menu **« 📍 Agences & DAB »** dans la barre latérale.\n"
            "2. Une carte interactive HD s'affiche avec plus de 21 agences et DABs en Tunisie (Tunis, Sousse, Sfax, Nabeul, Bizerte, etc.).\n"
            "3. Vous pouvez filtrer par type (**Agence** ou **DAB 24h/24**) et rechercher par ville.\n"
            "4. Cliquez sur un repère pour voir l'adresse exacte, les horaires d'ouverture et calculer l'itinéraire direct !"
        )

    # 12. Ouvrir un Nouveau Compte Bancaire
    elif has_match(raw, coll, ["ouvrir compte", "nouveau compte", "creer compte", "nouvo compt", "hal compte", "compte jdid", "compt jdid", "deuxieme compte", "autre compte"]) or ("compt" in raw and any(w in raw for w in ["jdid", "ouvr", "creer", "hal", "nouveau", "jadid"])):
        reply = (
            "➕ **Comment ouvrir un nouveau compte bancaire :**\n\n"
            "1. Rendez-vous sur votre **Tableau de Bord**.\n"
            "2. Cliquez sur le bouton **« ➕ Ouvrir un nouveau compte »**.\n"
            "3. Sélectionnez le type de compte désiré (Courant ou Épargne).\n"
            "4. Votre nouveau compte et sa carte virtuelle sont générés immédiatement avec un numéro de compte unique !"
        )

    # 13. Dépôt & Retrait d'argent
    elif has_match(raw, coll, ["depot", "deposer", "alimenter", "verser", "nsob", "sab flous", "retrait", "retirer", "njbed", "jbed flous", "espece", "cash"]):
        reply = (
            "💵 **Comment effectuer un dépôt ou un retrait :**\n\n"
            "• **Dépôt d'argent :** Ouvrez votre compte depuis le Tableau de Bord, descendez au formulaire 'Dépôt d'argent' et indiquez le montant. Les fonds sont crédités immédiatement.\n"
            "• **Retrait d'espèces :** Vous pouvez retirer des espèces à tout moment sur nos DABs 24/7 (menu 'Agences & DAB'), ou simuler un retrait sécurisé directement depuis l'espace de votre compte avec votre code PIN."
        )

    # 14. Commander un Chéquier
    elif has_match(raw, coll, ["chequier", "cheque", "carnet de cheque", "carnet", "demander chequier"]):
        reply = (
            "🧾 **Comment commander un chéquier :**\n\n"
            "1. Sur votre **Tableau de Bord**, cliquez sur votre compte courant.\n"
            "2. Allez dans l'onglet **« Services »**.\n"
            "3. Cliquez sur **« Demander un chéquier »**.\n"
            "4. Sélectionnez le carnet souhaité (25 ou 50 feuillets) et validez. Votre chéquier sera mis à votre disposition dans votre agence."
        )

    # 15. Journal d'activité & Sécurité (2FA, Face ID, Zero Trust)
    elif has_match(raw, coll, ["journal", "audit", "log", "logs", "activite", "securite", "2fa", "otp", "face id", "biometrie", "zero trust"]):
        reply = (
            "🛡️ **Sécurité & Journal d'activité :**\n\n"
            "• **Journal d'activité :** Rendez-vous dans **« 🛡️ Journal d'activité »** pour visualiser l'historique complet et infalsifiable de chaque opération (connexions, virements, paiements, modifications).\n"
            "• **Sécurité Zero Trust :** Dans vos paramètres, configurez la double authentification (**2FA OTP**) et la biométrie (**Face ID**) pour une protection absolue de votre compte."
        )

    # 16. Offre Prime (VIP)
    elif has_match(raw, coll, ["prime", "vip", "abonnement prime", "offre prime", "carte noire", "black card"]):
        reply = (
            "🌟 **Avantages de l'Offre Prime :**\n\n"
            "L'adhésion Prime (20 DT/an) vous confère des privilèges exclusifs :\n"
            "• Plafonds de paiement et de retrait personnalisables en direct.\n"
            "• Carte bancaire Black Edition haut de gamme.\n"
            "• Gratuité totale sur le renouvellement de carte.\n"
            "• Assistance prioritaire auprès de nos conseillers."
        )

    # 17. Réclamation, Problème ou Contact Conseiller / Admin
    elif has_match(raw, coll, ["reclamation", "plainte", "litige", "probleme", "mochkla", "mouchkla", "ghalta", "arnaque", "conseiller", "admin", "administrateur", "support", "aide humaine", "contacter", "erreur", "reclam"]):
        reply = (
            "📩 **Comment déposer une réclamation ou contacter nos conseillers :**\n\n"
            "1. Cliquez sur **« Messagerie »** dans le menu latéral (rubrique Support).\n"
            "2. Cliquez sur le bouton **« ✉️ Nouveau message »**.\n"
            "3. Choisissez la catégorie de votre demande (Incident Carte, Virement, Crédit, Assurance, Autre).\n"
            "4. Détaillez votre problème ou réclamation et envoyez.\n\n"
            "Nos conseillers et administrateurs étudieront votre demande avec soin et résoudront votre problème dans les plus brefs délais ! 📩"
        )

    # 18. Fallback intelligent (Demande non comprise / hors champ)
    else:
        reply = (
            "Je ne peux pas répondre directement à cette demande spécifique. "
            "Si vous avez une réclamation, un problème ou une question particulière, veuillez vous rendre dans la Messagerie (menu Support). "
            "Nos conseillers et administrateurs étudieront votre demande avec soin et résoudront votre problème dans les plus brefs délais ! 📩"
        )

    return {"reply": reply}

# ==============================
# 📩 SECURE MESSAGING
# ==============================

@router.post("/messages/send")
def send_support_message(data: SupportMessageRequest, user=Depends(verify_token)):
    user_id = str(user["id"])
    
    new_message = {
        "user_id": user_id,
        "subject": data.subject,
        "category": data.category,
        "content": data.content,
        "sender": "USER",
        "status": "SENT",
        "timestamp": datetime.datetime.utcnow(),
        "is_read": False
    }
    
    support_collection.insert_one(new_message)
    
    # Simulate an automated bank receipt (optional but nice)
    return {"message": "Message envoyé avec succès. Un conseiller l'étudiera rapidement."}

@router.get("/messages/history")
def get_message_history(user=Depends(verify_token)):
    user_id = str(user["id"])
    
    messages = list(support_collection.find(
        {"user_id": user_id}
    ).sort("timestamp", -1))
    
    for msg in messages:
        msg["id"] = str(msg["_id"])
        del msg["_id"]
        
    return messages
