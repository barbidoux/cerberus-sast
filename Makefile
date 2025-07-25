.PHONY: help install install-dev test test-cov lint format type-check clean docs run-example

# Variables
PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest
BLACK := $(PYTHON) -m black
RUFF := $(PYTHON) -m ruff
MYPY := $(PYTHON) -m mypy

# Couleurs pour l'affichage
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Affiche cette aide
	@echo "$(GREEN)Cerberus-SAST - Commandes disponibles$(NC)"
	@echo "======================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Installe Cerberus et ses dépendances
	@echo "$(GREEN)Installation de Cerberus-SAST...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install -e .
	@echo "$(GREEN)Installation du plugin C...$(NC)"
	cd plugins/cerberus-c-plugin && $(PIP) install -e .
	@echo "$(GREEN)✓ Installation terminée$(NC)"

install-dev: install ## Installe Cerberus avec les dépendances de développement
	@echo "$(GREEN)Installation des dépendances de développement...$(NC)"
	$(PIP) install -e ".[dev]"
	@echo "$(GREEN)✓ Installation dev terminée$(NC)"

test: ## Lance les tests unitaires
	@echo "$(GREEN)Lancement des tests...$(NC)"
	$(PYTEST) -v

test-cov: ## Lance les tests avec couverture
	@echo "$(GREEN)Lancement des tests avec couverture...$(NC)"
	$(PYTEST) --cov=cerberus --cov-report=term-missing --cov-report=html
	@echo "$(GREEN)✓ Rapport de couverture généré dans htmlcov/$(NC)"

lint: ## Vérifie le code avec ruff
	@echo "$(GREEN)Vérification du code avec ruff...$(NC)"
	$(RUFF) check cerberus/
	$(RUFF) check plugins/cerberus-c-plugin/cerberus_c_plugin/
	@echo "$(GREEN)✓ Aucun problème détecté$(NC)"

format: ## Formate le code avec black
	@echo "$(GREEN)Formatage du code avec black...$(NC)"
	$(BLACK) cerberus/
	$(BLACK) plugins/cerberus-c-plugin/cerberus_c_plugin/
	$(BLACK) tests/
	@echo "$(GREEN)✓ Code formaté$(NC)"

type-check: ## Vérifie les types avec mypy
	@echo "$(GREEN)Vérification des types avec mypy...$(NC)"
	$(MYPY) cerberus/
	@echo "$(GREEN)✓ Vérification des types terminée$(NC)"

clean: ## Nettoie les fichiers temporaires
	@echo "$(GREEN)Nettoyage des fichiers temporaires...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	rm -rf .cerberus_cache/
	rm -f *.sarif results.json results.html
	@echo "$(GREEN)✓ Nettoyage terminé$(NC)"

run-example: ## Analyse le fichier d'exemple vulnérable
	@echo "$(GREEN)Analyse du fichier d'exemple...$(NC)"
	$(PYTHON) -m cerberus scan examples/vulnerable.c
	@echo ""
	@echo "$(YELLOW)Pour plus d'options:$(NC)"
	@echo "  cerberus scan examples/vulnerable.c --format sarif -o results.sarif"
	@echo "  cerberus scan examples/vulnerable.c --format html -o results.html"

check: lint type-check test ## Lance toutes les vérifications (lint, types, tests)
	@echo "$(GREEN)✓ Toutes les vérifications sont passées !$(NC)"

dev: install-dev ## Configure l'environnement de développement complet
	@echo "$(GREEN)Configuration de pre-commit...$(NC)"
	pre-commit install 2>/dev/null || echo "$(YELLOW)pre-commit non installé$(NC)"
	@echo "$(GREEN)✓ Environnement de développement prêt$(NC)"

release: check ## Prépare une release (vérifie tout d'abord)
	@echo "$(GREEN)Préparation de la release...$(NC)"
	@echo "$(YELLOW)N'oubliez pas de:$(NC)"
	@echo "  1. Mettre à jour le CHANGELOG"
	@echo "  2. Bumper la version dans __init__.py et pyproject.toml"
	@echo "  3. Créer un tag git"
	@echo "  4. Pousser le tag: git push origin --tags"

# Commandes Docker (pour le futur)
docker-build: ## Construit l'image Docker
	@echo "$(YELLOW)Docker support à venir dans la v1.1$(NC)"

docker-run: ## Lance Cerberus dans Docker
	@echo "$(YELLOW)Docker support à venir dans la v1.1$(NC)"

.DEFAULT_GOAL := help