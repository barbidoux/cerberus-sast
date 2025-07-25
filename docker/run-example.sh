#!/bin/bash
# Script de démonstration pour Cerberus-SAST Docker
# Exécute un scan complet sur les fichiers d'exemple et génère des rapports

set -e  # Arrêter en cas d'erreur

# Configuration
EXAMPLE_DIR="/app/docker"
OUTPUT_DIR="/output"
CONFIG_FILE="$EXAMPLE_DIR/.cerberus.yml"
EXAMPLE_FILE="$EXAMPLE_DIR/example.c"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction d'affichage avec couleurs
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
echo "================================================================="
echo "          🛡️  CERBERUS-SAST DOCKER DEMONSTRATION  🛡️"
echo "================================================================="
echo ""

# Vérification des prérequis
log_info "Vérification de l'environnement..."

if [ ! -f "$EXAMPLE_FILE" ]; then
    log_error "Fichier d'exemple non trouvé: $EXAMPLE_FILE"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    log_error "Fichier de configuration non trouvé: $CONFIG_FILE"
    exit 1
fi

# Création du répertoire de sortie
mkdir -p "$OUTPUT_DIR"
log_success "Répertoire de sortie créé: $OUTPUT_DIR"

# Affichage des informations système
log_info "Informations système:"
echo "  - Version Cerberus: $(cerberus --version 2>/dev/null || echo 'Unknown')"
echo "  - Python: $(python --version)"
echo "  - Répertoire de travail: $(pwd)"
echo "  - Fichier à analyser: $EXAMPLE_FILE"
echo ""

# Diagnostic du système
log_info "Diagnostic du système Cerberus..."
cerberus doctor || {
    log_warning "Le diagnostic a détecté des problèmes, mais continuons..."
}
echo ""

# Listing des règles disponibles
log_info "Règles disponibles:"
cerberus rules --severity HIGH | head -20
echo ""

# Scan principal avec différents formats
log_info "Lancement du scan principal..."

# 1. Scan avec sortie JSON
log_info "Génération du rapport JSON..."
cerberus scan "$EXAMPLE_DIR" \
    --config "$CONFIG_FILE" \
    --format json \
    --output "$OUTPUT_DIR/report.json" \
    --fail-on NONE \
    --verbose || {
    log_warning "Le scan a terminé avec des warnings (normal pour la démo)"
}

# 2. Scan avec sortie SARIF
log_info "Génération du rapport SARIF..."
cerberus scan "$EXAMPLE_DIR" \
    --config "$CONFIG_FILE" \
    --format sarif \
    --output "$OUTPUT_DIR/report.sarif" \
    --fail-on NONE || {
    log_warning "Le scan a terminé avec des warnings (normal pour la démo)"
}

# 3. Scan avec sortie HTML
log_info "Génération du rapport HTML..."
cerberus scan "$EXAMPLE_DIR" \
    --config "$CONFIG_FILE" \
    --format html \
    --output "$OUTPUT_DIR/report.html" \
    --fail-on NONE || {
    log_warning "Le scan a terminé avec des warnings (normal pour la démo)"
}

# 4. Création d'une baseline
log_info "Création d'une baseline..."
cerberus baseline "$EXAMPLE_DIR" \
    --config "$CONFIG_FILE" \
    --output "$OUTPUT_DIR/baseline.json" || {
    log_warning "Création de baseline avec warnings"
}

# 5. Scan avec comparaison à la baseline
log_info "Scan avec comparaison à la baseline..."
cerberus scan "$EXAMPLE_DIR" \
    --config "$CONFIG_FILE" \
    --compare-to-baseline "$OUTPUT_DIR/baseline.json" \
    --format json \
    --output "$OUTPUT_DIR/incremental.json" \
    --fail-on NONE || {
    log_warning "Scan incrémental avec warnings"
}

# Génération d'un résumé
log_info "Génération du résumé d'exécution..."

cat > "$OUTPUT_DIR/execution_summary.txt" << EOF
=== CERBERUS-SAST DOCKER DEMO EXECUTION SUMMARY ===
Date: $(date)
Hostname: $(hostname)
User: $(whoami)

Files analyzed:
$(find "$EXAMPLE_DIR" -name "*.c" -o -name "*.h" | wc -l) C/C++ files

Output files generated:
$(ls -la "$OUTPUT_DIR" | grep -v "^d" | wc -l) files in $OUTPUT_DIR

Report files:
- report.json: Main findings in JSON format
- report.sarif: SARIF format for tool integration
- report.html: Human-readable HTML report
- baseline.json: Baseline snapshot for incremental scans
- incremental.json: New findings since baseline
- execution_summary.txt: This summary

Configuration used: $CONFIG_FILE

EOF

# Affichage du résumé des fichiers générés
echo ""
log_success "Scan terminé! Fichiers générés dans $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR/"

# Statistiques des findings si le fichier JSON existe
if [ -f "$OUTPUT_DIR/report.json" ]; then
    echo ""
    log_info "Statistiques des vulnérabilités détectées:"
    
    # Extraction des statistiques avec jq si disponible, sinon affichage brut
    if command -v jq >/dev/null 2>&1; then
        echo "  - Total findings: $(jq '.stats.total_findings // 0' "$OUTPUT_DIR/report.json")"
        echo "  - Files scanned: $(jq '.stats.files_scanned // 0' "$OUTPUT_DIR/report.json")"
        echo "  - By severity:"
        jq -r '.stats.findings_by_severity // {} | to_entries[] | "    - \(.key): \(.value)"' "$OUTPUT_DIR/report.json" 2>/dev/null || echo "    (unable to parse)"
    else
        echo "  - Voir le fichier $OUTPUT_DIR/report.json pour les détails"
    fi
fi

# Message final
echo ""
echo "================================================================="
log_success "Démonstration Cerberus-SAST terminée avec succès!"
echo ""
echo "Prochaines étapes:"
echo "  1. Examinez les rapports dans $OUTPUT_DIR/"
echo "  2. Ouvrez report.html dans un navigateur"
echo "  3. Intégrez report.sarif dans votre pipeline CI/CD"
echo "  4. Utilisez baseline.json pour les scans incrémentaux"
echo ""
echo "Pour une utilisation interactive:"
echo "  docker run -it --rm -v \$(pwd)/output:/output cerberus-sast bash"
echo "================================================================="