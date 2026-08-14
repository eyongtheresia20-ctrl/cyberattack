import os
import sys
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            # Suppress header and footer on cover page
            return
        
        self.saveState()
        
        # Colors
        primary_color = colors.HexColor("#0F172A")
        text_muted = colors.HexColor("#64748B")
        border_color = colors.HexColor("#CBD5E1")
        
        # Header (Top of page)
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(primary_color)
        self.drawString(54, 802, "PHISHGUARD")
        self.setFont("Helvetica", 8)
        self.setFillColor(text_muted)
        self.drawString(115, 802, "— Cahier de Conception et de Réalisation Technique (Version Académique)")
        
        self.setStrokeColor(border_color)
        self.setLineWidth(0.5)
        self.line(54, 794, 541, 794)
        
        # Footer (Bottom of page)
        self.line(54, 48, 541, 48)
        self.setFont("Helvetica", 8)
        self.setFillColor(text_muted)
        self.drawString(54, 34, "CONFIDENTIEL — Plateforme Web Intelligente de Détection et d'Analyse des Cybermenaces")
        
        page_text = f"Page {self._pageNumber} sur {page_count}"
        self.drawRightString(541, 34, page_text)
        
        self.restoreState()


def create_phishguard_pdf(output_filename):
    doc = SimpleDocTemplate(
        output_filename,
        pagesize=A4,
        leftMargin=54,  # ~1.9 cm
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    # Styles
    styles = getSampleStyleSheet()
    
    # Custom Palette
    c_primary = colors.HexColor("#0F172A")     # Slate 900
    c_secondary = colors.HexColor("#0284C7")   # Sky 600
    c_accent = colors.HexColor("#0D9488")      # Teal 600
    c_dark = colors.HexColor("#1E293B")        # Slate 800
    c_body = colors.HexColor("#334155")        # Slate 700
    c_bg_light = colors.HexColor("#F8FAFC")    # Slate 50
    c_bg_alt = colors.HexColor("#F1F5F9")      # Slate 100
    c_border = colors.HexColor("#E2E8F0")      # Slate 200
    c_alert = colors.HexColor("#DC2626")       # Red 600
    c_success = colors.HexColor("#16A34A")     # Green 600

    # Paragraph Styles
    style_cover_title = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=26,
        leading=32,
        textColor=c_primary,
        alignment=0,
        spaceAfter=12
    )
    
    style_cover_subtitle = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=18,
        textColor=c_secondary,
        alignment=0,
        spaceAfter=24
    )

    style_cover_meta = ParagraphStyle(
        'CoverMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=14,
        textColor=c_body
    )
    
    style_h1 = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True
    )

    style_h2 = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=c_secondary,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    style_h3 = ParagraphStyle(
        'Heading3_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=c_accent,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    style_body = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=c_body,
        spaceAfter=6
    )

    style_bullet = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=c_body,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    )

    style_callout = ParagraphStyle(
        'Callout_Text',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12.5,
        textColor=c_dark
    )

    style_table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=c_dark
    )

    style_table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=c_primary
    )

    style_table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    story = []

    # ==========================================
    # COVER PAGE / HEADER
    # ==========================================
    story.append(Spacer(1, 15))
    
    # Badge
    badge_style = ParagraphStyle('Badge', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, textColor=c_secondary)
    story.append(Paragraph("PROJET ACADÉMIQUE — SPÉCIFICATION TECHNIQUE & CONCEPTION SYSTEME", badge_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("PHISHGUARD", style_cover_title))
    story.append(Paragraph("Plateforme Web Intelligente de Détection, d’Analyse et de Suivi des Cybermenaces", style_cover_subtitle))
    
    story.append(HRFlowable(width="100%", thickness=2, color=c_secondary, spaceBefore=0, spaceAfter=15))

    meta_text = """
    <b>Document :</b> Cahier de Conception et de Réalisation Technique Complet (Architecture & Code)<br/>
    <b>Version :</b> 1.0 (Version de travail — Production Ready)<br/>
    <b>Choix d'Architecture recommandé :</b> Application Web full-stack (React + FastAPI + PostgreSQL + Scikit-Learn)<br/>
    <b>Chaîne Globale du Système :</b> Détecter &rarr; Analyser &rarr; Classifier &rarr; Expliquer &rarr; Surveiller &rarr; Conserver les Preuves &rarr; Signaler &rarr; Vérifier &rarr; Conseiller
    """
    story.append(Paragraph(meta_text, style_cover_meta))
    story.append(Spacer(1, 15))

    # Executive Note Callout Box
    exec_summary_html = """
    <b>Raison d'être du Choix Web :</b> Le choix d'une application Web s'impose comme l'architecture optimale pour PhishGuard. Elle permet de concilier la complexité des tableaux de bord d'analyse de menaces, la gestion centralisée des preuves numériques, la visualisation d'événements de sécurité en temps réel et le portail de vérification dédié aux enquêteurs. Ce document constitue la spécification exhaustive indispensable au développement, à la validation et à la soutenance du projet devant le jury.
    """
    summary_table = Table([[Paragraph(exec_summary_html, style_callout)]], colWidths=[487])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_bg_light),
        ('BOX', (0,0), (-1,-1), 1, c_secondary),
        ('PADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # Table of Contents Overview
    toc_html = """
    <b>Sommaire Exécutif du Cahier des Charges :</b><br/>
    1. Vision et Objectifs du Projet &nbsp;|&nbsp; 2. Définitions Essentielles & Glossaire &nbsp;|&nbsp; 3. Architecture des Modules Fonctionnels<br/>
    4. Analyse Approfondie d'une URL &nbsp;|&nbsp; 5. Analyse des Messages et Emails &nbsp;|&nbsp; 6. Surveillance de Site Web & Détection WAF/Logs<br/>
    7. Cas Fil Conducteur (Attaque Brute Force) &nbsp;|&nbsp; 8. Localisation IP & Limites &nbsp;|&nbsp; 9. Incidents & Portail Enquêteur<br/>
    10. Rôles et Droits (RBAC) &nbsp;|&nbsp; 11. Stack Technique & Architecture &nbsp;|&nbsp; 12. Modèle Logique de Données (MLD)<br/>
    13. Sécurité de PhishGuard &nbsp;|&nbsp; 14. Assistant Cybersécurité (IA) &nbsp;|&nbsp; 15. Structure Web (Sitemap UI)<br/>
    16. Use Cases &nbsp;|&nbsp; 17. Entraînement ML &nbsp;|&nbsp; 18. Pipeline Global &nbsp;|&nbsp; 19. Livrables à Développer &nbsp;|&nbsp; 20. Priorités MVP<br/>
    21. Plan de Réalisation &nbsp;|&nbsp; 22. Démonstration Jury &nbsp;|&nbsp; 23. Défense Jury &nbsp;|&nbsp; 24. Périmètre Non Couvert &nbsp;|&nbsp; 25. Checklist
    """
    toc_table = Table([[Paragraph(toc_html, style_body)]], colWidths=[487])
    toc_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_bg_alt),
        ('BOX', (0,0), (-1,-1), 0.5, c_border),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(toc_table)
    
    story.append(PageBreak())

    # ==========================================
    # SECTION 1: VISION ET OBJECTIF DU PROJET
    # ==========================================
    story.append(Paragraph("1. Vision et Objectifs du Projet PhishGuard", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))
    
    p1_text = """
    <b>PhishGuard</b> dépasse la simple notion de détecteur de phishing passif. Il s'agit d'une <b>plateforme web intégrée de Threat Intelligence, de détection d'attaques et de gestion des incidents de sécurité</b>. Le système est conçu pour répondre aux besoins opérationnels des utilisateurs (analyse directe d'éléments suspects) et des professionnels de la cybersécurité / enquêteurs (traçabilité, preuves numériques infalsifiables et rapports vérifiables).
    <br/><br/>
    Le système prend en charge la chaîne de traitement globale des cybermenaces :
    """
    story.append(Paragraph(p1_text, style_body))

    chain_steps = [
        ("Détecter", "Identifier la présence d'anomalies ou de caractéristiques suspectes dans les URLs, contenus et logs."),
        ("Analyser", "Extraire les variables techniques, examiner la réputation du domaine et classifier avec le Machine Learning."),
        ("Classifier", "Catégoriser précisément la menace (Phishing, SQLi, XSS, Brute Force, Scanning, Path Traversal, Bot)."),
        ("Expliquer", "Fournir des justifications claires et compréhensibles par l'humain via des modèles d'IA explicable."),
        ("Surveiller", "Ingérer et analyser les flux d'événements de sécurité d'un site autorisé (logs WAF / serveur HTTP)."),
        ("Conserver", "Sceller les preuves numériques avec des empreintes cryptographiques (Hash SHA-256) et horodatage."),
        ("Signaler", "Créer des incidents de sécurité structurés et exporter des rapports d'investigation officiels."),
        ("Vérifier", "Permettre à un enquêteur de contrôler l'authenticité et l'intégrité de l'analyse originale via un portail dédié."),
        ("Conseiller", "Délivrer des recommandations défensives et correctives contextualisées via un assistant IA d'aide à la décision.")
    ]

    for title, desc in chain_steps:
        story.append(Paragraph(f"• <b>{title} :</b> {desc}", style_bullet))
    
    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 2: DÉFINITIONS ESSENTIELLES
    # ==========================================
    story.append(Paragraph("2. Définitions Essentielles et Glossaire Technique", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    def_data = [
        [Paragraph("Terme", style_table_header), Paragraph("Définition Technique et Rôle dans PhishGuard", style_table_header)],
        [Paragraph("Phishing", style_table_cell_bold), Paragraph("Technique d'ingénierie sociale visant à tromper une victime pour lui dérober des identifiants, données bancaires ou installer un logiciel malveillant via des vecteurs imitant des entités légitimes (URL, Email, SMS).", style_table_cell)],
        [Paragraph("Cybermenace", style_table_cell_bold), Paragraph("Tout événement, vecteur ou entité susceptible de compromettre la confidentialité, l'intégrité ou la disponibilité d'un système d'information.", style_table_cell)],
        [Paragraph("Machine Learning", style_table_cell_bold), Paragraph("Branche de l'IA basée sur des algorithmes (ex: Random Forest) apprenant des motifs statistiques sur un jeu de données étiqueté afin de prédire la légitimité d'une menace.", style_table_cell)],
        [Paragraph("Intelligence Artificielle", style_table_cell_bold), Paragraph("Ensemble des modules d'analyse, d'explication du risque et d'assistance conversationnelle défensive intégrés à la plateforme.", style_table_cell)],
        [Paragraph("API (REST)", style_table_cell_bold), Paragraph("Interface logicielle standardisée (FastAPI) permettant l'interconnexion entre le Frontend, les moteurs ML/règles, la base de données et les services tiers.", style_table_cell)],
        [Paragraph("Threat Intelligence", style_table_cell_bold), Paragraph("Données externes de réputation et d'indicateurs de compromission (IoC) issues de services spécialisés (VirusTotal, Google Safe Browsing).", style_table_cell)],
        [Paragraph("Événement de Sécurité", style_table_cell_bold), Paragraph("Enregistrement individuel d'une activité réseau ou applicative (requête HTTP, tentative d'authentification, statut de réponse).", style_table_cell)],
        [Paragraph("Incident de Sécurité", style_table_cell_bold), Paragraph("Regroupement d'événements suspects atteignant un seuil de gravité nécessitant une investigation et un suivi opérationnel.", style_table_cell)],
        [Paragraph("Preuve Numérique", style_table_cell_bold), Paragraph("Donnée brute conservée (en-têtes HTTP, logs, corps de requête, horodatage, IP) garantissant la traçabilité de la détection.", style_table_cell)],
        [Paragraph("Hash (SHA-256)", style_table_cell_bold), Paragraph("Empreinte cryptographique à sens unique garantissant l'immutabilité et l'intégrité des rapports et analyses enregistrés.", style_table_cell)],
        [Paragraph("WAF / Reverse Proxy", style_table_cell_bold), Paragraph("Pare-feu applicatif ou serveur intermédiaire filtrant et transmettant les événements d'un site web autorisé vers PhishGuard.", style_table_cell)],
        [Paragraph("Géolocalisation IP", style_table_cell_bold), Paragraph("Estimation de l'emplacement réseau d'une adresse IP (Pays, ISP, ASN). Ne constitue pas une preuve de la localisation physique de l'attaquant.", style_table_cell)]
    ]

    t_defs = Table(def_data, colWidths=[120, 367])
    t_defs.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_defs)
    story.append(Spacer(1, 10))

    story.append(PageBreak())

    # ==========================================
    # SECTION 3: MODULES FONCTIONNELS
    # ==========================================
    story.append(Paragraph("3. Architecture des Modules Fonctionnels", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    story.append(Paragraph("PhishGuard s'articule autour de 6 modules fonctionnels majeurs interconnectés :", style_body))

    mod_data = [
        [Paragraph("Module", style_table_header), Paragraph("Fonctions Clés et Description Operationnelle", style_table_header)],
        [Paragraph("1. Analyse de Menaces", style_table_cell_bold), Paragraph("Analyse multi-vecteurs (URL, Message SMS/Chat, Email). Extraction automatique des caractéristiques, exécution du modèle ML, corrélation par moteur de règles, interrogation des APIs Threat Intelligence et génération du score de risque.", style_table_cell)],
        [Paragraph("2. Surveillance de Site Web", style_table_cell_bold), Paragraph("Ingestion d'événements de sécurité en provenance d'un site autorisé (logs HTTP, tentative d'accès, WAF). Normalisation et détection automatique des attaques (SQLi, XSS, Brute Force, Scanning, Path Traversal, Bots).", style_table_cell)],
        [Paragraph("3. Gestion des Incidents", style_table_cell_bold), Paragraph("Création automatique ou manuelle d'incidents de sécurité qualifiés (LOW, MEDIUM, HIGH, CRITICAL). Agrégation des preuves numériques, attribution d'IDs uniques (INC-2026-XXXX) et gestion du cycle de vie (Ouvert, En cours, Résolu).", style_table_cell)],
        [Paragraph("4. Portail Enquêteur & Vérification", style_table_cell_bold), Paragraph("Interface réservée aux agents habilités. Recherche de rapports par Report ID / Code, récupération de l'analyse originale non modifiable en base, contrôle d'intégrité par Hash SHA-256 et validation de l'enquête.", style_table_cell)],
        [Paragraph("5. Assistant Cybersécurité IA", style_table_cell_bold), Paragraph("Chatbot défensif contextualisé basé sur LLM. Explique le verdict des détections et fournit des guides de remediation pas-à-pas adaptés aux vulnérabilités identifiées.", style_table_cell)],
        [Paragraph("6. Administration & Governance", style_table_cell_bold), Paragraph("Gestion des utilisateurs et rôles (RBAC), configuration des clés d'APIs externes, surveillance de la santé du système et traçabilité globale (Audit Trail).", style_table_cell)]
    ]

    t_mods = Table(mod_data, colWidths=[130, 357])
    t_mods.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_mods)
    story.append(Spacer(1, 12))

    # ==========================================
    # SECTION 4: ANALYSE D'UNE URL
    # ==========================================
    story.append(Paragraph("4. Analyse Approfondie d'une URL (ML & Threat Intelligence)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    url_flow_text = """
    <b>Workflow Technique de Traitement d'une URL :</b><br/>
    <code>Utilisateur &rarr; Saisie URL &rarr; Backend FastAPI (Validation & Sanitization) &rarr; Extracteur de Caractéristiques &rarr; Prédiction Random Forest + Moteur de Règles &rarr; Interrogation APIs Threat Intel (VirusTotal / Google Safe Browsing) &rarr; Calcul du Score de Risque Global &rarr; Génération Explication IA &rarr; Sauvegarde DB & Historique</code>
    """
    story.append(Paragraph(url_flow_text, style_body))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Caractéristiques Techniques Extraites de l'URL :", style_h2))
    
    url_feats = [
        ("Caractéristiques Lexicales", "Longueur totale de l'URL, nombre de points, tirets, sous-domaines, présence de caractères normés suspect (@, %, double slash //)."),
        ("Signaux d'Hôte & Réseau", "Présence d'une adresse IP directe (IPv4/IPv6) à la place du nom de domaine, analyse de l'utilisation d'un port non standard (ex: :8080, :8888)."),
        ("Certificat SSL/TLS & HTTPS", "Vérification du protocole (HTTPS vs HTTP), validité du certificat SSL, émetteur et durée de validité du domaine."),
        ("Mots-Clés de Hameçonnage", "Présence de mots-clés à haut risque dans l'URL (ex: <i>login, verify, account, update, banking, paypal, secure, signin</i>)."),
        ("Analyse des Redirections", "Détection des raccourcisseurs d'URL (bit.ly, tinyurl) et suivi des chaînes de redirections HTTP jusqu'à la destination finale."),
        ("Indicateurs Domain & WHOIS", "Âge du nom de domaine, date de création récente (< 30 jours = risque élevé), masquage WHOIS anonyme.")
    ]

    for title, desc in url_feats:
        story.append(Paragraph(f"• <b>{title} :</b> {desc}", style_bullet))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Algorithme de Machine Learning — Random Forest Classifier :", style_h2))
    
    rf_text = """
    Pour la version 1.0, l'algorithme <b>Random Forest</b> est sélectionné pour des raisons d'efficacité éprouvée :
    <br/>
    • <b>Gestion d'attributs hétérogènes :</b> Combine parfaitement des variables numériques (longueurs, comptes) et catégorielles (booléens SSL, présence d'IP).<br/>
    • <b>Résistance au surapprentissage (Overfitting) :</b> L'agrégation d'arbres de décision multiples garantit une excellente généralisation.<br/>
    • <b>Explicabilité (Feature Importance) :</b> Permet d'extraire les poids des caractéristiques les plus déterminantes dans la classification pour alimenter l'assistant IA.<br/>
    • <b>Métriques d'évaluation requises :</b> Accuracy (&ge; 95%), Precision (&ge; 94%), Recall (&ge; 93%), F1-Score (&ge; 94%) et validation par Matrice de Confusion.
    """
    story.append(Paragraph(rf_text, style_body))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 5: ANALYSE MESSAGES ET EMAILS
    # ==========================================
    story.append(Paragraph("5. Analyse des Messages (SMS/Social) et des Emails", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    story.append(Paragraph("<b>5.1. Analyse des Messages / SMS</b>", style_h2))
    msg_text = """
    L'utilisateur soumet le texte d'un message suspect (SMS, WhatsApp, message réseau social). Le backend applique une analyse sémantique et lexicale combinée :
    <br/>
    • <b>Extraction automatique des URLs :</b> Identification et isolation des liens contenus dans le texte pour analyse par le module URL.<br/>
    • <b>Détection d'urgence artificielle :</b> Recherche de formules coercitives (ex: <i>"Compte bloqué sous 24h", "Action immédiate requise", "Dernier avertissement"</i>).<br/>
    • <b>Démarchage et demandes financières :</b> Détection des appels au virement, demande de codes OTP ou de cartes cadeaux.<br/>
    • <b>Usurpation d'identité (Impersonation) :</b> Détection d'imitation de banques, administrations (Impôts, Ameli) ou services de livraison (Chronopost, Colissimo).
    """
    story.append(Paragraph(msg_text, style_body))

    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>5.2. Analyse des Emails Suspects</b>", style_h2))
    email_text = """
    Pour le MVP, l'email peut être analysé via le copier-coller du corps/en-têtes ou le dépôt d'un fichier <code>.eml</code> ou <code>.msg</code> :
    <br/>
    • <b>Analyse des en-têtes (Headers) :</b> Vérification de la cohérence entre l'adresse expéditeur apparente (<code>From:</code>) et l'adresse réelle de retour (<code>Reply-To:</code> / <code>Return-Path:</code>).<br/>
    • <b>Protocoles d'Authentification Email :</b> Analyse des résultats SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail) et DMARC.<br/>
    • <b>Analyse des liens et pièces jointes :</b> Vérification de toutes les URLs intégrées et analyse de la dangerosité des extensions de fichiers joints (ex: <code>.exe, .scr, .iso, .vbs, .xlsm</code>).
    """
    story.append(Paragraph(email_text, style_body))

    story.append(PageBreak())

    # ==========================================
    # SECTION 6: SURVEILLANCE DU SITE WEB
    # ==========================================
    story.append(Paragraph("6. Surveillance de Site Web & Détection d'Attaques sur Site Autorisé", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    warn_box = """
    <b>Point Essentiel d'Architecture :</b> Une simple URL externe ne permet pas de connaître les attaques visant un site. Pour assurer cette fonction, PhishGuard reçoit des événements/logs envoyés par un site autorisé (via API, agent WAF, reverse proxy ou environnement de test sécurisé).
    """
    w_table = Table([[Paragraph(warn_box, style_callout)]], colWidths=[487])
    w_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#FEF2F2")),
        ('BOX', (0,0), (-1,-1), 1, c_alert),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(w_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Flux d'Ingestion des Logs et Événements de Sécurité :", style_h2))
    site_flow = """
    <code>Site Autorisé (Serveur HTTP / WAF) &rarr; API Ingestion Logs PhishGuard &rarr; Normalisation JSON &rarr; Moteur de Règles + Détection Anomalies &rarr; Classification de l'Attaque &rarr; Création d'Incident + Sauvegarde Preuves &rarr; Alerte Dashboard</code>
    """
    story.append(Paragraph(site_flow, style_body))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Attaques Couvertes dans le Prototype PhishGuard :", style_h2))

    attacks_table_data = [
        [Paragraph("Catégorie d'Attaque", style_table_header), Paragraph("Signature / Motif de Détection", style_table_header), Paragraph("Niveau de Risque", style_table_header)],
        [Paragraph("SQL Injection (SQLi)", style_table_cell_bold), Paragraph("Présence de mots-clés SQL suspects dans les paramètres d'URL ou corps POST (<code>UNION SELECT, OR 1=1, DROP TABLE, SLEEP()</code>).", style_table_cell), Paragraph("CRITICAL", style_table_cell_bold)],
        [Paragraph("Cross-Site Scripting (XSS)", style_table_cell_bold), Paragraph("Injection de balises HTML/JS dans les requêtes (<code>&lt;script&gt;, onerror=, javascript:</code>).", style_table_cell), Paragraph("HIGH", style_table_cell)],
        [Paragraph("Brute Force Auth", style_table_cell_bold), Paragraph("Répétition anormale de requêtes POST sur <code>/login</code> échouées depuis une même IP (&gt; 5 tentatives / minute).", style_table_cell), Paragraph("HIGH", style_table_cell)],
        [Paragraph("Scanning / Reconnaissance", style_table_cell_bold), Paragraph("Recherche automatisée d'URI sensibles (<code>/.env, /admin, /wp-login.php, /phpmyadmin</code>) générant de multiples erreurs 404.", style_table_cell), Paragraph("MEDIUM", style_table_cell)],
        [Paragraph("Path Traversal", style_table_cell_bold), Paragraph("Tentatives d'accès aux fichiers système via la séquence <code>../..</code> (ex: <code>/etc/passwd, c:\\boot.ini</code>).", style_table_cell), Paragraph("HIGH", style_table_cell)],
        [Paragraph("Comportement Bot / User-Agent", style_table_cell_bold), Paragraph("Utilisation de User-Agents suspects de scanners d'attaque connus (ex: <i>sqlmap, nikto, nmap, python-requests sans identité</i>).", style_table_cell), Paragraph("MEDIUM", style_table_cell)],
        [Paragraph("Anomalie de Trafic", style_table_cell_bold), Paragraph("Pic soudain de débit ou de requêtes réseau hors norme provenant d'un sous-réseau spécifique.", style_table_cell), Paragraph("LOW - MEDIUM", style_table_cell)]
    ]

    t_atk = Table(attacks_table_data, colWidths=[120, 287, 80])
    t_atk.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_atk)
    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 7: EXEMPLE CONCRET D'ANALYSE
    # ==========================================
    story.append(Paragraph("7. Cas Fil Conducteur — Analyse et Qualification d'une Attaque", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    story.append(Paragraph("Exemple de Déroulement d'un Incidents Brute Force (INC-2026-001) :", style_h2))

    case_study_text = """
    1. <b>Réception des Événements :</b> L'API d'ingestion reçoit 15 requêtes HTTP POST consécutives dirigées vers <code>POST /api/v1/auth/login</code> en l'espace de 8 secondes depuis l'IP source <code>198.51.100.45</code>.<br/>
    2. <b>Analyse du Motif :</b> Le moteur d'analyse statistique détecte un taux d'échec de 100% avec le code HTTP <code>401 Unauthorized</code> et un intervalle moyen entre requêtes de 530 ms.<br/>
    3. <b>Classification :</b> L'attaque est automatiquement catégorisée sous l'étiquette <b>Brute Force / Authentification</b>.<br/>
    4. <b>Attribution de Gravité :</b> Définie sur <b>HIGH</b> (Score de risque : 85/100).<br/>
    5. <b>Création de l'Incident :</b> Enregistrement immédiat dans la base sous l'identifiant <b>INC-2026-001</b>.<br/>
    6. <b>Scellement des Preuves :</b> Capture de l'IP source, User-Agent, horodatage exact, en-têtes HTTP et génération de l'empreinte Hash <code>SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</code>.<br/>
    7. <b>Alerte & Rapport :</b> Notification immédiate sur le Tableau de Bord de l'administrateur du site et mise à disposition du rapport téléchargeable.
    """
    story.append(Paragraph(case_study_text, style_body))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 8: LOCALISATION IP ET LIMITES
    # ==========================================
    story.append(Paragraph("8. Localisation de la Source & Limites Techniques (Plaidoirie Jury)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    geoip_text = """
    PhishGuard enrichit chaque adresse IP analysée avec des données de Threat Intelligence réseau (Pays, Ville approximative, ASN, Opérateur ISP). 
    <br/><br/>
    <b>Avertissement de Rigueur Scientifique et Juridique :</b><br/>
    La géolocalisation IP représente une <b>localisation réseau apparente</b>. Elle ne constitue en aucun cas une preuve de la position géographique réelle ni de l'identité physique de l'attaquant. Les cybercriminels utilisent fréquemment des relais anonymiseurs (VPN, Proxies SOCKS, réseau Tor, serveurs Cloud compromis ou réseaux de machines zombies / Botnets) pour masquer l'origine réelle du trafic.
    """
    story.append(Paragraph(geoip_text, style_body))

    quote_box = """
    <b>Déclaration de référence à soutenir devant le jury :</b><br/>
    <i>« Le système PhishGuard fournit des indicateurs techniques et une localisation apparente de la source réseau afin de faciliter l'investigation opérationnelle. L'identification de l'auteur réel nécessite impérativement des requêtes judiciaires et des vérifications complémentaires auprès des fournisseurs d'accès. »</i>
    """
    q_table = Table([[Paragraph(quote_box, style_callout)]], colWidths=[487])
    q_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_bg_light),
        ('BOX', (0,0), (-1,-1), 1, c_accent),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(q_table)

    story.append(PageBreak())

    # ==========================================
    # SECTION 9: INCIDENTS ET PORTAIL ENQUÊTEUR
    # ==========================================
    story.append(Paragraph("9. Gestion des Incidents, Rapports & Portail de Vérification Enquêteur", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    story.append(Paragraph("PhishGuard intègre un mécanisme complet de chaîne de traçabilité des preuves numériques :", style_body))

    invest_chain_text = """
    <code>Analyse Originale (ANL-2026-000458) &rarr; Incident Qualifié (INC-2026-000127) &rarr; Génération du Rapport Officiel + Empreinte Hash SHA-256 &rarr; Soumission à l'Enquêteur &rarr; Saisie du Report ID dans le Portail Enquêteur &rarr; Extractions de l'Analyse Originale de la DB PhishGuard &rarr; Contrôle d'Intégrité par Hash &rarr; Validation / Rejet</code>
    """
    story.append(Paragraph(invest_chain_text, style_body))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Contenu Réglémentaire du Rapport d'Incident :", style_h2))

    report_fields = [
        ("Identifiants Uniques", "Report ID (ex: <i>REP-2026-9941</i>) et Analysis ID d'origine (ex: <i>ANL-2026-000458</i>)."),
        ("Informations Déclarant", "Identité ou rôle de l'utilisateur ayant soumis l'élément, selon la politique de confidentialité."),
        ("Horodatage Précis", "Date et heure exactes de la détection au format ISO-8601 avec fuseau horaire (UTC)."),
        ("Objet Analysé", "URL complète, extrait de message, structure de l'email ou logs HTTP ciblés."),
        ("Qualifications du Risque", "Type d'attaque identifiée, score de risque (0-100) et niveau de gravité (LOW, MEDIUM, HIGH, CRITICAL)."),
        ("Preuves & Indicateurs", "Extraits de logs bruts, indicateurs réseau (IP, ASN, User-Agent) et résultats des contrôles externes."),
        ("Scellement d'Intégrité", "Empreinte Hash SHA-256 calculée sur l'ensemble des données d'analyse originales."),
        ("Statut de l'Enquête", "Statut du rapport dans le portail (<i>En attente, Validé, Rejeté, En cours d'investigation</i>).")
    ]

    for title, desc in report_fields:
        story.append(Paragraph(f"• <b>{title} :</b> {desc}", style_bullet))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 10: RÔLES ET DROITS (RBAC)
    # ==========================================
    story.append(Paragraph("10. Matrice des Rôles et Droits d'Accès (RBAC)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    role_data = [
        [Paragraph("Rôle", style_table_header), Paragraph("Périmètre d'Autorisation et Actions Permises", style_table_header)],
        [Paragraph("Utilisateur Standard", style_table_cell_bold), Paragraph("• Lancer des analyses d'URLs, de messages et d'emails.<br/>• Enregistrer ses propres sites autorisés pour la surveillance.<br/>• Consulter l'historique de ses propres analyses et alertes.<br/>• Générer un rapport d'incident et le soumettre à la cellule d'enquête.<br/>• Interagir avec l'Assistant Cybersécurité IA.", style_table_cell)],
        [Paragraph("Enquêteur / Agent", style_table_cell_bold), Paragraph("• Accéder au Portail Enquêteur sécurisé.<br/>• Rechercher tout rapport d'incident via son Report ID ou Code unique.<br/>• Extraire l'analyse originale scellée en base de données.<br/>• Effectuer la vérification d'intégrité cryptographique (Hash SHA-256).<br/>• Mettre à jour le statut de l'enquête (Validé, Classé sans suite, Transmis).", style_table_cell)],
        [Paragraph("Administrateur", style_table_cell_bold), Paragraph("• Gestion complète des comptes utilisateurs et attribution des rôles.<br/>• Configuration des clés d'APIs externes (VirusTotal, OpenAI, GeoIP).<br/>• Monitoring de la santé des services, réentraînement du modèle ML.<br/>• Consultation des journaux d'audit technique (Audit Logs).", style_table_cell)]
    ]

    t_roles = Table(role_data, colWidths=[120, 367])
    t_roles.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_roles)
    story.append(Spacer(1, 10))

    story.append(PageBreak())

    # ==========================================
    # SECTION 11: ARCHITECTURE TECHNIQUE
    # ==========================================
    story.append(Paragraph("11. Architecture Technique et Stack Logicielle", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    arch_data = [
        [Paragraph("Couche System", style_table_header), Paragraph("Technologie Sélectionnée", style_table_header), Paragraph("Rôle et Responsabilité Technique", style_table_header)],
        [Paragraph("Frontend UI", style_table_cell_bold), Paragraph("React 18 + Vite + Tailwind CSS", style_table_cell), Paragraph("Interface web dynamique, tableaux de bord interactifs, formulaires d'analyse et affichage des graphiques.", style_table_cell)],
        [Paragraph("Backend API", style_table_cell_bold), Paragraph("Python 3.11 + FastAPI", style_table_cell), Paragraph("API REST asynchrone haute performance, authentification JWT, validation Pydantic et logique métier.", style_table_cell)],
        [Paragraph("Engine ML", style_table_cell_bold), Paragraph("Scikit-Learn + Joblib + Pandas", style_table_cell), Paragraph("Extraction des features, exécution du modèle Random Forest et calcul des scores de prédiction.", style_table_cell)],
        [Paragraph("Base de Données", style_table_cell_bold), Paragraph("PostgreSQL (SQLite dev)", style_table_cell), Paragraph("Stockage relationnel persistant des utilisateurs, analyses, événements, preuves, incidents et audit logs.", style_table_cell)],
        [Paragraph("IA & Explications", style_table_cell_bold), Paragraph("API LLM (OpenAI / Claude / Gemini)", style_table_cell), Paragraph("Génération de résumés d'explication du risque et alimentation du Chatbot défensif.", style_table_cell)],
        [Paragraph("Threat Intelligence", style_table_cell_bold), Paragraph("VirusTotal API v3 + Safe Browsing", style_table_cell), Paragraph("Vérification externe de la réputation des domaines, URLs et répertoires malveillants connus.", style_table_cell)],
        [Paragraph("IP Intelligence", style_table_cell_bold), Paragraph("GeoIP2 / IP-API Service", style_table_cell), Paragraph("Enrichissement des adresses IP source (Pays, Ville, ASN, Opérateur).", style_table_cell)],
        [Paragraph("Conteneurisation", style_table_cell_bold), Paragraph("Docker & Docker Compose", style_table_cell), Paragraph("Déploiement reproductible multi-services (Frontend, Backend, DB).", style_table_cell)]
    ]

    t_arch = Table(arch_data, colWidths=[100, 150, 237])
    t_arch.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_arch)
    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 12: MODÈLE LOGIQUE DE DONNÉES
    # ==========================================
    story.append(Paragraph("12. Modèle Logique de Données (MLD / Schema PostgreSQL)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    mld_text = """
    <b>Entités Principales de la Base de Données PhishGuard :</b>
    <br/>
    • <b>User :</b> <code>id, email, password_hash, full_name, role_id, is_active, created_at</code><br/>
    • <b>Role :</b> <code>id, name (ADMIN, USER, INVESTIGATOR), description</code><br/>
    • <b>Analysis :</b> <code>id, user_id, type (URL, MESSAGE, EMAIL), target_input, overall_risk_score, risk_level, status, created_at</code><br/>
    • <b>URLAnalysis :</b> <code>id, analysis_id, domain, ip_address, has_ssl, url_length, num_dots, num_hyphens, has_at_symbol, is_whois_recent</code><br/>
    • <b>MessageAnalysis :</b> <code>id, analysis_id, sender_info, is_urgent_detected, extracted_urls_count, suspicion_score</code><br/>
    • <b>MLPrediction :</b> <code>id, analysis_id, model_version, confidence_score, predicted_label, feature_importance_json</code><br/>
    • <b>RuleResult :</b> <code>id, analysis_id, rule_code, rule_name, is_triggered, risk_impact</code><br/>
    • <b>ExternalCheck :</b> <code>id, analysis_id, service_name (VIRUSTOTAL, SAFE_BROWSING), verdict_positives, raw_response_json</code><br/>
    • <b>Website :</b> <code>id, owner_user_id, domain_name, api_key, is_monitored, created_at</code><br/>
    • <b>SecurityEvent :</b> <code>id, website_id, timestamp, source_ip, http_method, request_path, status_code, user_agent, raw_headers</code><br/>
    • <b>Attack :</b> <code>id, security_event_id, attack_type (SQLI, XSS, BRUTE_FORCE, SCANNING, PATH_TRAVERSAL), severity, confidence</code><br/>
    • <b>Evidence :</b> <code>id, attack_id, evidence_type, raw_payload, hash_sha256, captured_at</code><br/>
    • <b>Incident :</b> <code>id, website_id, incident_code (INC-2026-XXX), title, severity, status, created_at</code><br/>
    • <b>IncidentReport :</b> <code>id, incident_id, analysis_id, report_code (REP-2026-XXX), integrity_hash, report_pdf_path, created_at</code><br/>
    • <b>ReportVerification :</b> <code>id, report_id, investigator_user_id, is_integrity_valid, decision, verified_at</code><br/>
    • <b>AuditLog :</b> <code>id, user_id, action, target_entity, ip_address, timestamp</code>
    """
    story.append(Paragraph(mld_text, style_body))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 13: SÉCURITÉ DE PHISHGUARD
    # ==========================================
    story.append(Paragraph("13. Exigences de Sécurité et Bonnes Pratiques", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    sec_rules = [
        ("Chiffrement des Transmissions (HTTPS)", "Toutes les communications entre le client React et l'API FastAPI sont strictement chiffrées via TLS 1.3."),
        ("Protection des Mots de Passe", "Hachage sécurisé des mots de passe en base de données avec l'algorithme <b>Argon2id</b> ou <b>bcrypt</b> avec sel unique."),
        ("Authentification & Autorisation", "Authentification basée sur des jetons <b>JWT (JSON Web Tokens)</b> avec temps d'expiration court et contrôle d'accès strict (RBAC)."),
        ("Sécurisation des Clés API Tiers", "Stockage exclusif des clés API externes (VirusTotal, LLM) dans les variables d'environnement du backend. Aucune clé dans le code client."),
        ("Validation Stricte des Entrées (Input Validation)", "Sanitization systématique de toutes les entrées utilisateur pour empêcher les injections SQL, XSS et Command Injection."),
        ("Limitation de Débit (Rate Limiting)", "Application de règles de Rate Limiting sur les endpoints FastAPI sensibles pour contrer les attaques par déni de service (DoS)."),
        ("Traçabilité et Audit Trail", "Journalisation immuable de toutes les actions administratives et des accès au portail enquêteur dans la table <code>AuditLog</code>.")
    ]

    for title, desc in sec_rules:
        story.append(Paragraph(f"• <b>{title} :</b> {desc}", style_bullet))

    story.append(PageBreak())

    # ==========================================
    # SECTION 14: CHATBOT CYBERSÉCURITÉ
    # ==========================================
    story.append(Paragraph("14. Assistant Cybersécurité Intelligente (Chatbot Défensif)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    chat_text = """
    L'assistant conversationnel PhishGuard est directement <b>interconnecté au contexte d'analyse actif</b>. 
    <br/><br/>
    <b>Exemple de Scénario Opérationnel :</b><br/>
    Si le système détecte une injection SQL sur un site surveillé, l'utilisateur peut interroger le chatbot : <i>« Pourquoi cette requête est-elle classée SQL Injection et comment sécuriser mon code PHP ? »</i>. Le chatbot analyse les événements scellés et fournit une réponse défensive contextualisée (ex: recommandation des requêtes préparées PDO / ORM).
    <br/><br/>
    <b>Garde-fous Éthiques et Sécurité :</b><br/>
    Le chatbot est strictement configuré pour fournir des <b>conseils exclusivement défensifs et de remediation</b>. Tout prompt utilisateur tentant d'utiliser l'assistant pour générer des scripts d'attaque ou exploiter une vulnérabilité est automatiquement rejeté.
    """
    story.append(Paragraph(chat_text, style_body))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 15: SITEMAP INTERFACE WEB
    # ==========================================
    story.append(Paragraph("15. Structure des Interfaces Web (Sitemap UI)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    sitemap_text = """
    <b>TABLEAU DE BORD UTILISATEUR & ADMINISTRATEUR :</b><br/>
    ├── <b>Vue d'Ensemble (Dashboard) :</b> Métriques clés, dernières détections, niveau de menace global.<br/>
    ├── <b>Analyser une URL :</b> Formulaire de saisie, options d'analyse, restitution détaillée et score.<br/>
    ├── <b>Analyser un Message / SMS :</b> Zone de texte, extraction automatique des liens, verdict sémantique.<br/>
    ├── <b>Analyser un Email :</b> Dépôt de fichier <code>.eml</code> ou en-têtes, contrôle SPF/DKIM.<br/>
    ├── <b>Mes Sites Surveillés :</b> Configuration des domaines autorisés, intégration des clés d'ingestion.<br/>
    ├── <b>Alertes & Événements WAF :</b> Visualisation en temps réel du flux de requêtes HTTP et attaques.<br/>
    ├── <b>Incidents & Rapports :</b> Liste des incidents (INC-2026-XXXX), génération de rapports PDF scellés.<br/>
    └── <b>Assistant Cybersécurité :</b> Interface conversationnelle d'aide à la décision.<br/>
    <br/>
    <b>PORTAIL ENQUÊTEUR (AGENT AUTORISÉ) :</b><br/>
    ├── <b>Rapports Reçus :</b> Liste des dossiers d'incidents transmis pour investigation.<br/>
    ├── <b>Rechercher un Rapport :</b> Moteur de recherche par Report ID / Code Hash.<br/>
    ├── <b>Module de Vérification d'Intégrité :</b> Comparaison cryptographique avec l'analyse originale DB.<br/>
    └── <b>Validation & Suivi :</b> Mise à jour des statuts d'enquête et export des pièces juridiques.
    """
    story.append(Paragraph(sitemap_text, style_body))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 16: CAS D'UTILISATION (USE CASES)
    # ==========================================
    story.append(Paragraph("16. Tableau Synthétique des Cas d'Utilisation (Use Cases)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    uc_data = [
        [Paragraph("Acteur", style_table_header), Paragraph("Code Use Case", style_table_header), Paragraph("Intitulé du Use Case", style_table_header), Paragraph("Objectif Métier", style_table_header)],
        [Paragraph("Utilisateur", style_table_cell_bold), Paragraph("UC-01", style_table_cell), Paragraph("Analyser une URL", style_table_cell), Paragraph("Obtenir un verdict immédiat et un score de risque sur une URL.", style_table_cell)],
        [Paragraph("Utilisateur", style_table_cell_bold), Paragraph("UC-02", style_table_cell), Paragraph("Analyser un Message/SMS", style_table_cell), Paragraph("Détecter les tentatives de hameçonnage et urgence artificielle.", style_table_cell)],
        [Paragraph("Utilisateur", style_table_cell_bold), Paragraph("UC-03", style_table_cell), Paragraph("Surveiller un Site Web", style_table_cell), Paragraph("Connecter les logs d'un site autorisé pour détecter les attaques.", style_table_cell)],
        [Paragraph("Utilisateur", style_table_cell_bold), Paragraph("UC-04", style_table_cell), Paragraph("Générer un Rapport", style_table_cell), Paragraph("Créer un dossier scellé avec hash pour transmission légale.", style_table_cell)],
        [Paragraph("Enquêteur", style_table_cell_bold), Paragraph("UC-05", style_table_cell), Paragraph("Rechercher un Rapport", style_table_cell), Paragraph("Retrouver un dossier via son Report ID ou son empreinte Hash.", style_table_cell)],
        [Paragraph("Enquêteur", style_table_cell_bold), Paragraph("UC-06", style_table_cell), Paragraph("Vérifier l'Intégrité", style_table_cell), Paragraph("Comparer la copie transmise avec l'analyse originale en base DB.", style_table_cell)],
        [Paragraph("Admin", style_table_cell_bold), Paragraph("UC-07", style_table_cell), Paragraph("Gérer la Plateforme", style_table_cell), Paragraph("Administrer les comptes, rôles, clés d'API et modèles ML.", style_table_cell)]
    ]

    t_uc = Table(uc_data, colWidths=[70, 50, 140, 227])
    t_uc.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_uc)

    story.append(PageBreak())

    # ==========================================
    # SECTION 17: PIPELINE MACHINE LEARNING
    # ==========================================
    story.append(Paragraph("17. Pipeline d'Entraînement et d'Inférence ML", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    ml_pipeline_text = """
    <code>Dataset Étiqueté (Phishing vs Légitime) &rarr; Nettoyage & Normalisation &rarr; Extraction des Caractéristiques &rarr; Séparation Train (80%) / Test (20%) &rarr; Entraînement Random Forest &rarr; Évaluation Métriques &rarr; Sauvegarde Modèle (.pkl) &rarr; Déploiement Endpoint FastAPI (/predict)</code>
    <br/><br/>
    <b>Métriques de Validation Obtenues lors de la Phase de Test :</b>
    """
    story.append(Paragraph(ml_pipeline_text, style_body))

    metrics_data = [
        [Paragraph("Métrique d'Évaluation", style_table_header), Paragraph("Formule Mathématique", style_table_header), Paragraph("Objectif Cible PhishGuard", style_table_header)],
        [Paragraph("Accuracy (Exactitude)", style_table_cell_bold), Paragraph("<code>(TP + TN) / (TP + TN + FP + FN)</code>", style_table_cell), Paragraph("&ge; 95.0%", style_table_cell_bold)],
        [Paragraph("Precision (Précision)", style_table_cell_bold), Paragraph("<code>TP / (TP + FP)</code> (Limite les fausses alertes)", style_table_cell), Paragraph("&ge; 94.0%", style_table_cell_bold)],
        [Paragraph("Recall (Rappel)", style_table_cell_bold), Paragraph("<code>TP / (TP + FN)</code> (Captures les vrais phishing)", style_table_cell), Paragraph("&ge; 93.0%", style_table_cell_bold)],
        [Paragraph("F1-Score", style_table_cell_bold), Paragraph("<code>2 * (Precision * Recall) / (Precision + Recall)</code>", style_table_cell), Paragraph("&ge; 94.0%", style_table_cell_bold)]
    ]

    t_met = Table(metrics_data, colWidths=[140, 220, 127])
    t_met.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_secondary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_met)
    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 18: PIPELINE GLOBAL DU SYSTÈME
    # ==========================================
    story.append(Paragraph("18. Diagramme du Pipeline Global du Système", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    pipe_diagram = """
    ┌────────────────────────────────────────────────────────────────────────────────────────┐
    │ ENTRÉE : URL / MESSAGE / EMAIL / ÉVÉNEMENTS LOGS SITE                                  │
    └───────────────────────────────────────────┬────────────────────────────────────────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │   FRONTEND REACT UI   │
                                    └───────────┬───────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │  BACKEND FASTAPI API  │
                                    │ (Auth, Validation)    │
                                    └───────────┬───────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
    ┌─────────────────────────┐  ┌─────────────────────────────┐  ┌───────────────────────────┐
    │   MODÈLE ML RANDOM      │  │  MOTEUR DE RÈGLES ET        │  │   SERVICES THREAT INTEL   │
    │   FOREST (.pkl)         │  │  SIGNATURES D'ATTAQUES      │  │ (VirusTotal, SafeBrowse)  │
    └────────────┬────────────┘  └──────────────┬──────────────┘  └─────────────┬─────────────┘
                 │                              │                               │
                 └──────────────────────────────┼───────────────────────────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │ MOTEUR DE CORRÉLATION │
                                    │ & SCORE DE RISQUE     │
                                    └───────────┬───────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼                                                             ▼
    ┌─────────────────────────┐                                   ┌───────────────────────────┐
    │ BASE DE DONNÉES DB      │                                   │ PREUVES, INCIDENTS &      │
    │ (Analyses, Historique)  │                                   │ RAPPORTS D'ENQUÊTE        │
    └────────────┬────────────┘                                   └─────────────┬─────────────┘
                 │                                                              │
                 ▼                                                              ▼
    ┌─────────────────────────┐                                   ┌───────────────────────────┐
    │ ASSISTANT IA CONTEXTUEL │                                   │ PORTAIL DE VÉRIFICATION   │
    │ & CONSEILS DÉFENSIFS    │                                   │ D'INTÉGRITÉ (HASH SHA256) │
    └─────────────────────────┘                                   └───────────────────────────┘
    """
    story.append(Paragraph(f"<pre style='font-size: 7px; leading: 8px;'>{pipe_diagram}</pre>", style_body))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 19: LIVRABLES À DÉVELOPPER
    # ==========================================
    story.append(Paragraph("19. Périmètre Fonctionnel à Développer (Livrables Logiciels)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    deliverables = [
        "<b>Frontend Web React :</b> Interfaces d'analyse, tableaux de bord interactifs, portail enquêteur et composants d'alertes.",
        "<b>API Backend FastAPI :</b> Services Web RESTful asynchrones, contrôles d'accès RBAC, gestion des sessions JWT.",
        "<b>Base de Données PostgreSQL :</b> Modèle relationnel complet (tables, clés étrangères, indexations et déclencheurs).",
        "<b>Module d'Analyse URL & Feature Engineering :</b> Script d'extraction des 15+ variables et pipeline d'inférence ML.",
        "<b>Modèle ML Random Forest :</b> Script d'entraînement, jeux de données étiquetés, validation et sérialisation <code>.pkl</code>.",
        "<b>Module d'Analyse Messages/Emails :</b> Analyseur sémantique et parser de fichiers d'emails (.eml).",
        "<b>Module de Ingestion Logs Site Autorisé :</b> API de collecte d'événements HTTP et classificateur d'attaques WAF.",
        "<b>Module de Gestion des Incidents & Preuves :</b> Moteur de scellement cryptographique Hash SHA-256 et génération PDF.",
        "<b>Portail Enquêteur :</b> Module de contrôle d'intégrité et de comparaison des empreintes d'analyse.",
        "<b>Assistant Cybersécurité :</b> Chatbot IA intégré orienté conseils défensifs."
    ]

    for d in deliverables:
        story.append(Paragraph(f"• {d}", style_bullet))

    story.append(PageBreak())

    # ==========================================
    # SECTION 20: MATRICE DE PRIORITÉS MVP
    # ==========================================
    story.append(Paragraph("20. Matrice des Priorités MVP (P1 / P2 / P3)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    prio_data = [
        [Paragraph("Priorité", style_table_header), Paragraph("Fonctionnalité", style_table_header), Paragraph("Justification Stratégique MVP", style_table_header)],
        [Paragraph("P1 (Indispensable)", style_table_cell_bold), Paragraph("Analyse URL + Modèle ML Random Forest", style_table_cell), Paragraph("Cœur névralgique de la détection de hameçonnage et valeur scientifique ML.", style_table_cell)],
        [Paragraph("P1 (Indispensable)", style_table_cell_bold), Paragraph("Analyse Messages & Emails", style_table_cell), Paragraph("Couverture complète des canaux d'ingénierie sociale.", style_table_cell)],
        [Paragraph("P1 (Indispensable)", style_table_cell_bold), Paragraph("Threat Intelligence (APIs Externes)", style_table_cell), Paragraph("Corroboration des prédictions internes par la réputation mondiale.", style_table_cell)],
        [Paragraph("P1 (Indispensable)", style_table_cell_bold), Paragraph("Surveillance Logs Site & Détection Attaques", style_table_cell), Paragraph("Démonstration de la protection applicative (SQLi, XSS, Brute Force).", style_table_cell)],
        [Paragraph("P1 (Indispensable)", style_table_cell_bold), Paragraph("Incidents, Preuves & Portail Enquêteur", style_table_cell), Paragraph("Prouve la traçabilité et l'immutabilité des preuves numériques.", style_table_cell)],
        [Paragraph("P1 (Indispensable)", style_table_cell_bold), Paragraph("Assistant Cybersécurité Chatbot", style_table_cell), Paragraph("Explication pédagogique et aide à la décision pour l'utilisateur.", style_table_cell)],
        [Paragraph("P2 (Important)", style_table_cell_bold), Paragraph("Système de Notifications Alertes Temps Réel", style_table_cell), Paragraph("Information instantanée en cas d'attaque critique détectée sur un site.", style_table_cell)],
        [Paragraph("P2 (Important)", style_table_cell_bold), Paragraph("Statistiques Avancées & Tendances", style_table_cell), Paragraph("Graphiques d'évolution temporelle des cybermenaces.", style_table_cell)],
        [Paragraph("P3 (Évolution)", style_table_cell_bold), Paragraph("Anomalies ML Avancées (Deep Learning/Unsupervised)", style_table_cell), Paragraph("Détection d'anomalies non supervisée après stabilisation du MVP.", style_table_cell)]
    ]

    t_prio = Table(prio_data, colWidths=[90, 170, 227])
    t_prio.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_bg_light]),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_prio)
    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 21: PLAN DE RÉALISATION
    # ==========================================
    story.append(Paragraph("21. Plan de Réalisation et Feuille de Route (12 Étapes)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    plan_steps = [
        ("Étape 1", "Validation définitive du cahier des charges, de l'architecture et des cas d'utilisation."),
        ("Étape 2", "Conception du schéma de base de données PostgreSQL, des spécifications d'API FastAPI et auth JWT."),
        ("Étape 3", "Développement du frontend React, de la charte graphique Tailwind et des dashboards de base."),
        ("Étape 4", "Collecte et préparation des jeux de données d'URLs, extraction de variables et entraînement ML."),
        ("Étape 5", "Intégration du moteur d'inférence ML Random Forest dans l'API backend PhishGuard."),
        ("Étape 6", "Implémentation du moteur de règles et interconnexion aux APIs Threat Intelligence (VirusTotal)."),
        ("Étape 7", "Développement du module d'analyse sémantique des messages et d'analyse des fichiers d'emails."),
        ("Étape 8", "Création du module d'ingestion de logs et du générateur d'événements de test pour sites autorisés."),
        ("Étape 9", "Développement du classificateur d'attaques applicatives (SQLi, XSS, Brute Force, Scanning, Path Traversal)."),
        ("Étape 10", "Implémentation de la chaîne d'incidents, scellement des preuves Hash SHA-256 et portail enquêteur."),
        ("Étape 11", "Intégration de l'Assistant Cybersécurité conversationnel basé sur l'IA explicative."),
        ("Étape 12", "Phase de recettes, tests d'intégration, audits de sécurité interne, documentation et préparation de la soutenance.")
    ]

    for step, title in plan_steps:
        story.append(Paragraph(f"• <b>{step} :</b> {title}", style_bullet))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 22: DÉMONSTRATION JURY
    # ==========================================
    story.append(Paragraph("22. Scénario Complet de Démonstration (Soutenance devant le Jury)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    demo_text = """
    <b>Déroulement Chronologique Récommandé de la Démonstration (15-20 minutes) :</b>
    <br/><br/>
    <b>Acte 1 : Soumission d'une URL de Hameçonnage Suspecte</b><br/>
    Saisie d'une URL contrefaite dans le formulaire. Le système exécute le modèle ML et les règles, interroge Threat Intel et affiche un verdict <b>HIGH RISK</b> avec le détail des caractéristiques suspectes et l'explication IA.
    <br/><br/>
    <b>Acte 2 : Analyse d'un Message SMS Frauduleux</b><br/>
    Copier-coller d'un SMS usurpant une banque avec urgence artificielle. PhishGuard isole le lien piège, analyse la sémantique et formule des recommandations défensives.
    <br/><br/>
    <b>Acte 3 : Surveillance d'un Site Web Autorisé & Détection d'Attaque</b><br/>
    Envoi d'une série de requêtes d'attaque (SQLi / Brute Force) vers le site de test surveillé. Le tableau de bord affiche instantanément la détection de l'attaque, la classification et la capture des preuves.
    <br/><br/>
    <b>Acte 4 : Génération et Vérification d'un Rapport d'Enquête</b><br/>
    Création d'un incident depuis l'attaque détectée et export du rapport scellé par Hash SHA-256. Basculement sur le <b>Portail Enquêteur</b> : l'agent recherche le rapport, le système compare l'empreinte avec la DB et confirme l'intégrité parfaite du dossier.
    <br/><br/>
    <b>Acte 5 : Assistance Cybersécurité Conversationnelle</b><br/>
    Interrogation du Chatbot IA sur les mesures de correction à apporter au site web suite à l'injection SQL détectée. Le chatbot fournit le code correctif sécurisé.
    """
    story.append(Paragraph(demo_text, style_body))

    story.append(PageBreak())

    # ==========================================
    # SECTION 23: RÉPONSES AUX QUESTIONS DU JURY
    # ==========================================
    story.append(Paragraph("23. Guide des Réponses Stratégiques aux Questions du Jury", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    q_answers = [
        ("Question : Pourquoi utiliser des APIs externes (VirusTotal) alors que vous avez un modèle ML ?",
         "Réponse : Le modèle ML est notre propre intelligence prédictive (propriétaire) capable de détecter des menaces 0-day non encore répertoriées. Les APIs externes apportent une corroboration de réputation mondiale. La valeur de PhishGuard réside dans la fusion et la corrélation de ces sources d'information."),

        ("Question : Une simple URL permet-elle de détecter toutes les attaques d'un site web ?",
         "Réponse : Non, et c'est une distinction clé de notre architecture. L'analyse d'URL évalue la dangerosité d'un lien sortant. La surveillance de site requiert l'ingestion des événements/logs internes d'un environnement autorisé pour détecter des attaques applicatives (SQLi, XSS, Brute Force)."),

        ("Question : Comment garantissez-vous qu'un rapport soumis par un utilisateur n'a pas été falsifié ?",
         "Réponse : L'enquêteur ne se fie pas au fichier fourni par l'utilisateur. Grâce au Report ID, le portail extrait directement l'analyse originale scellée en base de données et contrôle la correspondance exacte de l'empreinte Hash SHA-256."),

        ("Question : La géolocalisation IP permet-elle d'arrêter l'attaquant ?",
         "Réponse : Non. L'IP fournit une localisation réseau apparente utile pour l'investigation. L'identification physique de l'auteur nécessite des démarches judiciaires auprès des FAI car l'attaquant peut utiliser des VPN, Proxies ou le réseau Tor.")
    ]

    for q, a in q_answers:
        story.append(Paragraph(f"• <b>{q}</b>", style_h2))
        story.append(Paragraph(f"<i>{a}</i>", style_body))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 8))

    # ==========================================
    # SECTION 24: CE QU'IL NE FAUT PAS PROMETTRE
    # ==========================================
    story.append(Paragraph("24. Ce qu'il ne Faut PAS Promettre (Périmètre Non Couvert)", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    no_promises = [
        "Ne JAMAIS prétendre localiser physiquement l'adresse exacte d'un pirate à partir de son IP.",
        "Ne JAMAIS garantir l'identification automatique de l'identité civile du criminel.",
        "Ne JAMAIS affirmer que le système peut détecter 100% de toutes les cyberattaques existantes.",
        "Ne JAMAIS présenter PhishGuard comme un remplacement total d'un WAF commercial, SIEM, Antivirus ou SOC complet.",
        "Ne JAMAIS prétendre qu'un modèle ML est infaillible (toujours évoquer le taux de faux positifs/négatifs).",
        "Ne JAMAIS promettre le déclenchement automatique d'actions policières sans intervention humaine."
    ]

    for np in no_promises:
        story.append(Paragraph(f"• {np}", style_bullet))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 25: CHECKLIST FINALE
    # ==========================================
    story.append(Paragraph("25. Checklist Finale de Recette et Validation", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    chk_text = """
    ☐ Cahier des charges et architecture validés<br/>
    ☐ Modèle logique de données PostgreSQL déployé<br/>
    ☐ API FastAPI opérationnelle avec authentification JWT<br/>
    ☐ Jeu de données collecté et modèle ML Random Forest évalué<br/>
    ☐ Engine d'analyse URL avec extraction des 15+ features opérationnel<br/>
    ☐ Engine d'analyse des messages et emails opérationnel<br/>
    ☐ Intégration sécurisée de Threat Intelligence (VirusTotal)<br/>
    ☐ Ingestion de logs et détection d'attaques WAF (SQLi, XSS, Brute Force)<br/>
    ☐ Chaîne de gestion des incidents et scellement des preuves Hash SHA-256<br/>
    ☐ Portail de vérification enquêteur fonctionnel<br/>
    ☐ Assistant Cybersécurité conversationnel (Chatbot) intégré<br/>
    ☐ Cahier de recette, tests et dossier de démonstration finalisés
    """
    story.append(Paragraph(chk_text, style_body))

    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 26: CONCLUSION
    # ==========================================
    story.append(Paragraph("26. Conclusion et Synthèse du Projet", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=c_secondary, spaceBefore=2, spaceAfter=8))

    conclusion_text = """
    Le choix d'une **architecture Web full-stack** pour la plateforme **PhishGuard** est pleinement justifié. Il offre l'ergonomie, la puissance de traitement et la flexibilité nécessaires pour orchestrer l'ensemble des modules : détection d'analyse de contenu, surveillance d'événements applicatifs, scellement de preuves cryptographiques et portail d'investigation pour les enquêteurs.
    <br/><br/>
    <b>Formule Synthétique à Retenir pour le Projet :</b><br/>
    <code>ENTRÉE &rarr; ANALYSE &rarr; ML / RÈGLES &rarr; THREAT INTELLIGENCE &rarr; CORRÉLATION &rarr; SCORE DE RISQUE &rarr; EXPLICATION IA &rarr; PREUVES &rarr; INCIDENT &rarr; RAPPORT &rarr; VÉRIFICATION ENQUÊTEUR &rarr; CONSEILS DÉFENSIFS</code>
    """
    story.append(Paragraph(conclusion_text, style_body))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF Successfully Generated at: {output_filename}")

if __name__ == "__main__":
    out_path = os.path.join(r"d:\cyberattack", "PhishGuard_Cahier_de_Conception_et_de_Realisation.pdf")
    create_phishguard_pdf(out_path)
