# Guide de Contribution

Merci de votre intérêt pour contribuer à Cerberus-SAST ! Ce guide vous aidera à démarrer.

## 🎯 Comment contribuer

### 1. Signaler des bugs

- Vérifiez d'abord que le bug n'a pas déjà été signalé
- Ouvrez une issue avec un titre clair et une description détaillée
- Incluez :
  - Version de Cerberus
  - Étapes pour reproduire
  - Comportement attendu vs observé
  - Logs d'erreur (si applicable)

### 2. Proposer des améliorations

- Ouvrez une issue pour discuter de votre idée
- Expliquez le cas d'usage et les bénéfices
- Attendez un retour avant de commencer le développement

### 3. Soumettre du code

1. **Fork** le repository
2. **Clone** votre fork : `git clone https://github.com/votre-username/cerberus.git`
3. **Créez une branche** : `git checkout -b feature/ma-fonctionnalite`
4. **Commitez** avec des messages clairs : `git commit -m "feat: ajoute la détection XYZ"`
5. **Push** vers votre fork : `git push origin feature/ma-fonctionnalite`
6. **Ouvrez une Pull Request**

## 🛠️ Environnement de développement

### Installation

```bash
# Cloner le repo
git clone https://github.com/cerberus-sast/cerberus.git
cd cerberus

# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Installer en mode développement
pip install -e ".[dev]"

# Installer les plugins
cd plugins/cerberus-c-plugin
pip install -e .
cd ../..
```

### Tests

```bash
# Lancer tous les tests
pytest

# Avec couverture
pytest --cov=cerberus --cov-report=html

# Tests spécifiques
pytest tests/test_core/test_config.py
```

### Qualité du code

```bash
# Formatage automatique
black cerberus/

# Linting
ruff check cerberus/

# Type checking
mypy cerberus/
```

## 📝 Standards de code

### Style

- Suivre PEP 8
- Utiliser Black pour le formatage (ligne de 100 caractères)
- Docstrings Google style pour toutes les fonctions publiques

### Exemple de docstring

```python
def analyze_file(file_path: Path, rules: List[Rule]) -> List[Finding]:
    """
    Analyse un fichier avec les règles spécifiées.
    
    Args:
        file_path: Chemin du fichier à analyser
        rules: Liste des règles à appliquer
        
    Returns:
        Liste des vulnérabilités trouvées
        
    Raises:
        FileNotFoundError: Si le fichier n'existe pas
    """
```

### Commits

Format des messages de commit :

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types :
- `feat`: Nouvelle fonctionnalité
- `fix`: Correction de bug
- `docs`: Documentation
- `style`: Formatage, missing semi-colons, etc.
- `refactor`: Refactoring
- `test`: Ajout de tests
- `chore`: Maintenance, dépendances, etc.

Exemple :
```
feat(rules): ajoute la détection des integer overflows

Implémente la détection des débordements d'entiers en C
en utilisant l'analyse de flux de données.

Closes #123
```

## 🧩 Créer un nouveau plugin

1. Copier le template dans `plugins/cerberus-template-plugin/`
2. Renommer selon votre langage
3. Implémenter l'interface `LanguagePlugin`
4. Ajouter des règles YAML
5. Écrire des tests
6. Documenter dans un README

Structure minimale :
```
plugins/cerberus-xyz-plugin/
├── pyproject.toml
├── README.md
├── cerberus_xyz_plugin/
│   ├── __init__.py
│   ├── plugin.py
│   └── rules/
│       └── basic.yml
└── tests/
    └── test_plugin.py
```

## 🔍 Ajouter des règles

### Format YAML

```yaml
rules:
  - id: lang-category-description
    message: |
      Description claire du problème.
      Comment le corriger.
    severity: HIGH  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    languages:
      - c
    pattern: dangerous_function($ARG)
    metadata:
      cwe: "CWE-XXX"
      owasp: "A01:2021"
      confidence: HIGH
      references:
        - https://example.com/doc
    autofix:
      pattern: safe_function($ARG, limit)
```

### Guidelines pour les règles

1. **Minimiser les faux positifs** : Mieux vaut manquer un vrai problème que noyer l'utilisateur
2. **Messages clairs** : Expliquer le problème ET la solution
3. **Métadonnées complètes** : CWE, OWASP, références
4. **Tests exhaustifs** : Cas positifs, négatifs, edge cases
5. **Documentation** : Exemples de code vulnérable et sécurisé

## 📊 Checklist avant PR

- [ ] Le code suit les standards du projet
- [ ] Les tests passent (`pytest`)
- [ ] Nouveau code testé (couverture > 80%)
- [ ] Documentation mise à jour
- [ ] Pas de secrets ou données sensibles
- [ ] Messages de commit clairs
- [ ] PR liée aux issues concernées

## 🤝 Code de conduite

- Soyez respectueux et inclusif
- Acceptez les critiques constructives
- Focalisez-vous sur ce qui est mieux pour la communauté
- Montrez de l'empathie envers les autres contributeurs

## 📬 Contact

- Issues GitHub pour les bugs et features
- Discussions GitHub pour les questions générales
- Email : cerberus@example.com pour les sujets sensibles

Merci de contribuer à rendre le code plus sûr ! 🛡️