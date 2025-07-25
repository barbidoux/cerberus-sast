# Dockerfile pour Cerberus-SAST
# Image Docker autonome pour analyse de sécurité statique

FROM python:3.11-slim

# Métadonnées de l'image
LABEL maintainer="Cerberus Team <cerberus@example.com>"
LABEL description="Cerberus-SAST - Moteur d'analyse de sécurité statique modulaire"
LABEL version="1.0.0"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV CERBERUS_HOME=/app
ENV CERBERUS_OUTPUT=/output

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Création des répertoires de travail
WORKDIR /app

# Copie des fichiers de requirements d'abord (pour optimiser le cache Docker)
COPY requirements.txt requirements-dev.txt ./

# Installation des dépendances Python (sans cerberus PyPI pour éviter conflit)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements-dev.txt && \
    pip uninstall -y cerberus || true

# Copie de tout le code source
COPY . .

# Installation de Cerberus-SAST en mode editable avec PYTHONPATH explicite
RUN pip install -e . && \
    pip uninstall -y cerberus || true

# Installation du plugin C
RUN cd plugins/cerberus-c-plugin && \
    pip install -e .

# Vérification de l'installation
RUN python -c "import sys; print('Python path:', sys.path)" && \
    python -c "from cerberus.cli.commands import main; print('✅ Import successful')" && \
    cerberus --help

# Création du répertoire de sortie
RUN mkdir -p $CERBERUS_OUTPUT && \
    chmod 755 $CERBERUS_OUTPUT

# Ajout du script d'exemple
COPY docker/run-example.sh /usr/local/bin/run-example.sh
RUN chmod +x /usr/local/bin/run-example.sh

# Exposition du répertoire de sortie comme volume
VOLUME ["/output"]

# Point d'entrée par défaut
ENTRYPOINT ["cerberus"]
CMD ["--help"]

# Commandes alternatives disponibles:
# docker run cerberus-sast scan /app/examples/
# docker run cerberus-sast rules
# docker run cerberus-sast doctor
# docker run --rm -v $(pwd)/output:/output cerberus-sast /usr/local/bin/run-example.sh