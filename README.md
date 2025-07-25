# Cerberus-SAST

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

Cerberus-SAST est un moteur d'analyse de sécurité statique (SAST) modulaire et extensible, conçu pour s'intégrer facilement dans les pipelines CI/CD modernes.

## 🚀 Caractéristiques principales

- **Modulaire** : Architecture basée sur des plugins pour supporter plusieurs langages
- **Performant** : Analyse parallèle et mise en cache intelligente
- **Précis** : Minimisation des faux positifs grâce à des règles contextuelles
- **Intégré** : Support natif de SARIF pour l'intégration avec GitHub, GitLab, etc.
- **Extensible** : API simple pour créer vos propres plugins et règles

## 📦 Installation

### 🐳 Docker (Recommandé)

La façon la plus simple d'utiliser Cerberus-SAST est avec Docker :

```bash
# Build de l'image
docker build -t cerberus-sast .

# Exécution rapide avec démonstration
docker run --rm -v $(pwd)/output:/output cerberus-sast /usr/local/bin/run-example.sh

# Scan d'un projet local
docker run --rm -v $(pwd):/workspace -v $(pwd)/output:/output \
  cerberus-sast scan /workspace --format json --output /output/results.json

# Mode interactif
docker run -it --rm -v $(pwd)/output:/output cerberus-sast bash
```

### Depuis PyPI (à venir)

```bash
pip install cerberus-sast
```

### Depuis les sources

```bash
# Cloner le repository
git clone https://github.com/barbidoux/cerberus-sast.git
cd cerberus-sast

# Installer en mode développement
pip install -e .

# Installer avec les dépendances de développement
pip install -r requirements-dev.txt
```

### Installation du plugin C

```bash
cd plugins/cerberus-c-plugin
pip install -e .
```

## 🔧 Usage

### Analyse basique

```bash
# Analyser le répertoire courant
cerberus scan

# Analyser un répertoire spécifique
cerberus scan /chemin/vers/projet

# Générer un rapport SARIF
cerberus scan --format sarif --output results.sarif
```

### Configuration

Créez un fichier `.cerberus.yml` à la racine de votre projet :

```yaml
version: "1.0"

scan:
  # Sévérité minimale pour faire échouer le build
  fail_on_severity: HIGH
  
  # Chemins à exclure
  exclude_paths:
    - "**/tests/**"
    - "**/vendor/**"
    - "**/*.min.js"
  
  # Activer le cache
  cache_enabled: true

plugins:
  c:
    enabled: true
    options:
      c_standard: c11
    rulesets:
      buffer-overflow:
        enabled: true
        severity_threshold: MEDIUM
```

### 🐳 Usage Docker

#### Commandes de base

```bash
# Voir l'aide
docker run --rm cerberus-sast --help

# Lister les règles disponibles
docker run --rm cerberus-sast rules

# Diagnostic du système
docker run --rm cerberus-sast doctor

# Démonstration complète
docker run --rm -v $(pwd)/output:/output cerberus-sast /usr/local/bin/run-example.sh
```

#### Scan de votre projet

```bash
# Scan avec configuration par défaut
docker run --rm -v $(pwd):/workspace -v $(pwd)/output:/output \
  cerberus-sast scan /workspace

# Scan avec configuration personnalisée
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/output:/output \
  -v $(pwd)/.cerberus.yml:/app/.cerberus.yml \
  cerberus-sast scan /workspace --config /app/.cerberus.yml --format sarif --output /output/results.sarif
```

### Intégration CI/CD

#### GitHub Actions avec Docker

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  cerberus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Cerberus image
        run: docker build -t cerberus-sast .
      
      - name: Run Cerberus scan
        run: |
          mkdir -p output
          docker run --rm \
            -v $(pwd):/workspace \
            -v $(pwd)/output:/output \
            cerberus-sast scan /workspace --format sarif --output /output/results.sarif
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: output/results.sarif
```

#### GitLab CI avec Docker

```yaml
cerberus-sast:
  image: docker:20.10.16
  services:
    - docker:20.10.16-dind
  script:
    - docker build -t cerberus-sast .
    - mkdir -p output
    - docker run --rm -v $(pwd):/workspace -v $(pwd)/output:/output 
        cerberus-sast scan /workspace --format sarif --output /output/gl-sast-report.json
  artifacts:
    reports:
      sast: output/gl-sast-report.json
    paths:
      - output/
```

#### Installation native (sans Docker)

```yaml
# GitHub Actions - Installation native
cerberus-native:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install Cerberus
      run: |
        pip install -r requirements.txt
        pip install -e .
    
    - name: Run Cerberus scan
      run: cerberus scan --format sarif --output results.sarif
    
    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results.sarif
```

## 🧩 Plugins disponibles

| Plugin | Langage | Version | Statut |
|--------|---------|---------|--------|
| cerberus-c-plugin | C/C++ | 1.0.0 | ✅ Stable |
| cerberus-python-plugin | Python | - | 🚧 En développement |
| cerberus-java-plugin | Java | - | 📋 Planifié |
| cerberus-js-plugin | JavaScript | - | 📋 Planifié |

## 📝 Création de plugins

Pour créer votre propre plugin, implémentez l'interface `LanguagePlugin` :

```python
from cerberus.plugins.base import LanguagePlugin

class MonPlugin(LanguagePlugin):
    @property
    def name(self) -> str:
        return "mon-langage"
    
    @property
    def supported_extensions(self) -> List[str]:
        return [".ext"]
    
    # Implémenter les autres méthodes requises...
```

Consultez le [Guide de développement de plugins](docs/plugin-development.md) pour plus de détails.

## 🔍 Formats de sortie

- **Console** : Rapport coloré dans le terminal (par défaut)
- **JSON** : Format structuré pour l'intégration
- **SARIF** : Standard de l'industrie pour les outils SAST
- **HTML** : Rapport interactif pour la revue manuelle

## 🛡️ Sécurité

Cerberus-SAST suit les meilleures pratiques de sécurité :

- ✅ Analyse de dépendances intégrée
- ✅ Signatures GPG pour les releases
- ✅ Auto-analyse du code source
- ✅ Isolation des plugins

## 🐳 Guide Docker détaillé

### Structure de l'image

L'image Docker Cerberus-SAST contient :
- **Python 3.11** avec toutes les dépendances
- **Tree-sitter** et parsers pour C/C++, Python, JavaScript
- **Cerberus-SAST** préinstallé et configuré
- **Fichiers d'exemple** pour démonstration (`/app/docker/`)
- **Script de démonstration** (`/usr/local/bin/run-example.sh`)

### Variables d'environnement

| Variable | Valeur par défaut | Description |
|----------|-------------------|-------------|
| `CERBERUS_HOME` | `/app` | Répertoire d'installation |
| `CERBERUS_OUTPUT` | `/output` | Répertoire de sortie |
| `PYTHONUNBUFFERED` | `1` | Sortie Python non bufferisée |

### Volumes recommandés

| Volume local | Volume conteneur | Usage |
|--------------|------------------|-------|
| `$(pwd)` | `/workspace` | Code source à analyser |
| `$(pwd)/output` | `/output` | Rapports et résultats |
| `$(pwd)/.cerberus.yml` | `/app/.cerberus.yml` | Configuration |

### Exemples d'utilisation avancés

```bash
# Scan avec baseline
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/output:/output \
  cerberus-sast scan /workspace --compare-to-baseline /output/baseline.json

# Création de baseline
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/output:/output \
  cerberus-sast baseline /workspace --output /output/baseline.json

# Mode développement interactif
docker run -it --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/output:/output \
  --entrypoint bash \
  cerberus-sast

# Scan avec règles personnalisées
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/custom-rules:/app/custom-rules \
  -v $(pwd)/output:/output \
  cerberus-sast scan /workspace --config /app/.cerberus.yml
```

### Publication Docker Hub

```bash
# Build pour multiple architectures
docker buildx build --platform linux/amd64,linux/arm64 -t cerberus-sast:latest .

# Tag et push vers Docker Hub
docker tag cerberus-sast:latest your-username/cerberus-sast:1.0.0
docker push your-username/cerberus-sast:1.0.0
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez notre [Guide de contribution](CONTRIBUTING.md).

### Développement avec Docker

```bash
# Build de l'image de développement
docker build -f Dockerfile.dev -t cerberus-sast:dev .

# Tests dans le conteneur
docker run --rm -v $(pwd):/app cerberus-sast:dev python -m pytest

# Linting
docker run --rm -v $(pwd):/app cerberus-sast:dev ruff check .
```

## 📄 License

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements

Cerberus-SAST s'inspire des meilleures pratiques de projets comme Semgrep, SonarQube et Bandit.