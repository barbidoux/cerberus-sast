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

### Depuis PyPI (à venir)

```bash
pip install cerberus-sast
```

### Depuis les sources

```bash
# Cloner le repository
git clone https://github.com/cerberus-sast/cerberus.git
cd cerberus

# Installer en mode développement
pip install -e .

# Installer avec les dépendances de développement
pip install -e ".[dev]"
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

### Intégration CI/CD

#### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  cerberus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Cerberus
        run: |
          pip install cerberus-sast
          pip install cerberus-c-plugin
      
      - name: Run Cerberus scan
        run: cerberus scan --format sarif --output results.sarif
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
cerberus-sast:
  image: python:3.11
  script:
    - pip install cerberus-sast cerberus-c-plugin
    - cerberus scan --format sarif --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
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

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez notre [Guide de contribution](CONTRIBUTING.md).

## 📄 License

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements

Cerberus-SAST s'inspire des meilleures pratiques de projets comme Semgrep, SonarQube et Bandit.