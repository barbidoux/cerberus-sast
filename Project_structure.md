cerberus-sast/
├── pyproject.toml                  # Configuration du projet Python
├── README.md                       # Documentation principale
├── .gitignore                      # Fichiers à ignorer par Git
├── cerberus/                       # Package principal
│   ├── __init__.py
│   ├── __main__.py                 # Point d'entrée CLI
│   ├── cli/                        # Module CLI
│   │   ├── __init__.py
│   │   └── commands.py             # Commandes CLI
│   ├── core/                       # Moteur principal
│   │   ├── __init__.py
│   │   ├── engine.py               # Orchestrateur principal
│   │   ├── config.py               # Gestion de configuration
│   │   └── scanner.py              # Logique de scan
│   ├── plugins/                    # Système de plugins
│   │   ├── __init__.py
│   │   ├── base.py                 # Classe abstraite LanguagePlugin
│   │   └── manager.py              # Gestionnaire de plugins
│   ├── analysis/                   # Moteur d'analyse
│   │   ├── __init__.py
│   │   ├── ast_utils.py            # Utilitaires AST
│   │   └── rule_engine.py          # Moteur de règles
│   ├── reporting/                  # Module de reporting
│   │   ├── __init__.py
│   │   ├── formats.py              # Formats de sortie
│   │   └── sarif.py                # Support SARIF
│   └── utils/                      # Utilitaires
│       ├── __init__.py
│       └── logging.py              # Configuration logging
├── plugins/                        # Plugins externes
│   └── cerberus-c-plugin/          # Plugin C
│       ├── pyproject.toml
│       ├── cerberus_c_plugin/
│       │   ├── __init__.py
│       │   ├── plugin.py           # Implémentation du plugin C
│       │   └── rules/              # Règles YAML
│       │       └── c-buffer-overflow.yml
│       └── README.md
├── tests/                          # Tests unitaires
│   ├── __init__.py
│   └── test_core/
│       └── test_engine.py
└── examples/                       # Exemples
    └── vulnerable.c                # Code C vulnérable pour les tests