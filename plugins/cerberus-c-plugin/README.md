# Cerberus C Plugin

Plugin officiel pour l'analyse de code C/C++ dans Cerberus-SAST.

## 🚀 Installation

```bash
pip install cerberus-c-plugin
```

Ou depuis les sources :

```bash
cd plugins/cerberus-c-plugin
pip install -e .
```

## 📋 Règles incluses

### Sécurité - Buffer Overflow

- **c-buffer-overflow-strcpy** : Détecte l'utilisation dangereuse de `strcpy()`
- **c-buffer-overflow-gets** : Détecte l'utilisation de `gets()` (fonction dépréciée)
- **c-buffer-overflow-sprintf** : Détecte l'utilisation non sécurisée de `sprintf()`

### Sécurité - Format String

- **c-format-string-bug** : Détecte les vulnérabilités de format string

### Plus de règles à venir...

- Gestion mémoire (use-after-free, double-free)
- Integer overflow
- Injection de commandes
- Path traversal

## ⚙️ Configuration

Dans votre `.cerberus.yml` :

```yaml
plugins:
  c:
    enabled: true
    options:
      # Standard C à utiliser
      c_standard: c11
      
      # Inclure les fichiers C++
      include_cpp: true
    
    # Règles personnalisées
    custom_rules:
      - /chemin/vers/mes-regles-c.yml
    
    # Configuration des ensembles de règles
    rulesets:
      buffer-overflow:
        enabled: true
        severity_threshold: MEDIUM
```

## 🔧 Options disponibles

| Option | Type | Défaut | Description |
|--------|------|--------|-------------|
| `c_standard` | string | `c11` | Standard C à utiliser (c89, c90, c99, c11, c17, c18) |
| `include_cpp` | bool | `true` | Analyser aussi les fichiers C++ |

## 📝 Création de règles personnalisées

Créez un fichier YAML avec vos règles :

```yaml
rules:
  - id: ma-regle-c
    message: Description du problème et comment le corriger
    severity: HIGH
    languages:
      - c
    pattern: fonction_dangereuse($ARG)
    metadata:
      cwe: "CWE-XXX"
      category: "security"
    autofix:
      pattern: fonction_secure($ARG, limite)
```

## 🧪 Tests

Pour tester le plugin :

```bash
# Analyser un fichier C vulnérable
cerberus scan examples/vulnerable.c

# Avec rapport détaillé
cerberus scan examples/vulnerable.c --format json -o report.json
```

## 🤝 Contribution

Les contributions sont bienvenues ! Pour ajouter de nouvelles règles :

1. Créez un fichier YAML dans `cerberus_c_plugin/rules/`
2. Testez vos règles sur du code réel
3. Documentez les cas d'usage et les faux positifs connus
4. Soumettez une pull request

## 📚 Ressources

- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c)
- [OWASP - Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)