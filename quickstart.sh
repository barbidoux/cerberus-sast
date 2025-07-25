#!/bin/bash
# Script de démarrage rapide pour Cerberus-SAST

set -e

echo "🚀 Installation de Cerberus-SAST..."
echo "=================================="

# Vérifier Python 3.11+
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.11"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
    echo "❌ Python $required_version ou supérieur est requis (trouvé: $python_version)"
    exit 1
fi

echo "✅ Python $python_version détecté"

# Créer un environnement virtuel
echo ""
echo "📦 Création de l'environnement virtuel..."
python3 -m venv venv
source venv/bin/activate

# Installer Cerberus
echo ""
echo "📥 Installation de Cerberus-SAST..."
pip install --upgrade pip
pip install -e .

# Installer le plugin C
echo ""
echo "🔌 Installation du plugin C..."
cd plugins/cerberus-c-plugin
pip install -e .
cd ../..

# Installer les dépendances de développement (optionnel)
read -p "Installer les dépendances de développement ? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip install -e ".[dev]"
fi

# Tester l'installation
echo ""
echo "🧪 Test de l'installation..."
cerberus --version

# Analyser l'exemple vulnérable
echo ""
echo "🔍 Analyse d'un fichier d'exemple..."
cerberus scan examples/vulnerable.c

echo ""
echo "✨ Installation terminée avec succès!"
echo ""
echo "Pour commencer :"
echo "  source venv/bin/activate"
echo "  cerberus scan /chemin/vers/votre/code"
echo ""
echo "Documentation : https://github.com/cerberus-sast/cerberus"