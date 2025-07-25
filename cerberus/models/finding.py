"""
Modèles pour les findings (vulnérabilités détectées).

Ce module définit les structures de données standardisées pour représenter
les vulnérabilités trouvées par Cerberus-SAST.
"""

from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, validator


class Severity(str, Enum):
    """Niveaux de sévérité pour les vulnérabilités."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Location(BaseModel):
    """Localisation d'une vulnérabilité dans le code."""
    file_path: str = Field(..., description="Chemin du fichier")
    line: int = Field(..., ge=1, description="Numéro de ligne (>=1)")
    column: int = Field(..., ge=1, description="Numéro de colonne (>=1)")
    end_line: Optional[int] = Field(None, ge=1, description="Ligne de fin (optionnelle)")
    end_column: Optional[int] = Field(None, ge=1, description="Colonne de fin (optionnelle)")
    
    @validator('end_line')
    def validate_end_line(cls, v, values):
        if v is not None and 'line' in values and v < values['line']:
            raise ValueError("end_line doit être >= line")
        return v
    
    @validator('end_column') 
    def validate_end_column(cls, v, values):
        if (v is not None and 'column' in values and 
            'end_line' in values and values.get('end_line') == values.get('line') and
            v < values['column']):
            raise ValueError("end_column doit être >= column quand sur la même ligne")
        return v


class CodeSnippet(BaseModel):
    """Extrait de code avec contexte autour d'une vulnérabilité."""
    content: str = Field(..., description="Contenu de l'extrait")
    start_line: int = Field(..., ge=1, description="Première ligne de l'extrait")
    end_line: int = Field(..., ge=1, description="Dernière ligne de l'extrait")
    highlight_lines: List[int] = Field(default_factory=list, 
                                      description="Lignes à mettre en évidence")


class Fix(BaseModel):
    """Information pour corriger automatiquement une vulnérabilité."""
    pattern: str = Field(..., description="Pattern de remplacement")
    description: Optional[str] = Field(None, description="Description du fix")


class Finding(BaseModel):
    """
    Représentation standardisée d'une vulnérabilité détectée.
    
    Cette classe encapsule toutes les informations relatives à une vulnérabilité
    trouvée par Cerberus-SAST, incluant sa localisation, sa sévérité et les
    métadonnées associées.
    """
    
    # Identification
    rule_id: str = Field(..., description="Identifiant unique de la règle")
    message: str = Field(..., description="Message descriptif de la vulnérabilité")
    severity: Severity = Field(..., description="Niveau de sévérité")
    
    # Localisation
    location: Location = Field(..., description="Localisation dans le code")
    
    # Contexte code
    code_snippet: Optional[CodeSnippet] = Field(None, description="Extrait de code avec contexte")
    
    # Métadonnées
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Métadonnées de la règle")
    variables: Dict[str, str] = Field(default_factory=dict, 
                                     description="Variables capturées par le pattern")
    
    # Correction automatique
    fix: Optional[Fix] = Field(None, description="Information de correction automatique")
    
    # Informations techniques
    node_type: Optional[str] = Field(None, description="Type du nœud AST correspondant")
    confidence: Optional[str] = Field(None, description="Niveau de confiance")
    
    @classmethod
    def from_match(cls, 
                   rule_id: str,
                   message: str, 
                   severity: Severity,
                   file_path: Path,
                   match: Dict[str, Any],
                   metadata: Dict[str, Any] = None,
                   fix: Optional[Dict[str, str]] = None) -> 'Finding':
        """
        Crée un Finding à partir d'un match de règle.
        
        Args:
            rule_id: ID de la règle
            message: Message de la vulnérabilité
            severity: Sévérité
            file_path: Chemin du fichier
            match: Dictionnaire de correspondance avec line, column, snippet, etc.
            metadata: Métadonnées de la règle
            fix: Information de correction automatique
            
        Returns:
            Instance de Finding
        """
        location = Location(
            file_path=str(file_path),
            line=match.get("line", 1),
            column=match.get("column", 1)
        )
        
        code_snippet = None
        if "snippet" in match and match["snippet"]:
            # Parser le snippet pour extraire les informations de lignes
            snippet_lines = match["snippet"].split('\n')
            if snippet_lines:
                code_snippet = CodeSnippet(
                    content=match["snippet"],
                    start_line=max(1, location.line - 2),  # Approximation
                    end_line=location.line + 2,
                    highlight_lines=[location.line]
                )
        
        finding_fix = None
        if fix:
            finding_fix = Fix(
                pattern=fix.get("pattern", ""),
                description=fix.get("description")
            )
        
        return cls(
            rule_id=rule_id,
            message=message,
            severity=severity,
            location=location,
            code_snippet=code_snippet,
            metadata=metadata or {},
            variables=match.get("variables", {}),
            fix=finding_fix,
            node_type=match.get("node_type"),
            confidence=metadata.get("confidence") if metadata else None
        )
    
    def to_sarif_result(self) -> Dict[str, Any]:
        """
        Convertit le Finding au format SARIF.
        
        Returns:
            Dictionnaire représentant un result SARIF
        """
        # Mapping des sévérités Cerberus vers SARIF
        severity_mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error", 
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        
        sarif_result = {
            "ruleId": self.rule_id,
            "message": {
                "text": self.message
            },
            "level": severity_mapping.get(self.severity, "warning"),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": self.location.file_path
                        },
                        "region": {
                            "startLine": self.location.line,
                            "startColumn": self.location.column
                        }
                    }
                }
            ]
        }
        
        # Ajouter les informations de fin si disponibles
        if self.location.end_line:
            sarif_result["locations"][0]["physicalLocation"]["region"]["endLine"] = self.location.end_line
        if self.location.end_column:
            sarif_result["locations"][0]["physicalLocation"]["region"]["endColumn"] = self.location.end_column
        
        # Ajouter le snippet de code si disponible
        if self.code_snippet:
            sarif_result["locations"][0]["physicalLocation"]["contextRegion"] = {
                "startLine": self.code_snippet.start_line,
                "endLine": self.code_snippet.end_line,
                "snippet": {
                    "text": self.code_snippet.content
                }
            }
        
        # Ajouter les propriétés personnalisées
        if self.metadata or self.variables or self.node_type:
            properties = {}
            if self.metadata:
                properties.update(self.metadata)
            if self.variables:
                properties["variables"] = self.variables
            if self.node_type:
                properties["node_type"] = self.node_type
            if self.confidence:
                properties["confidence"] = self.confidence
                
            sarif_result["properties"] = properties
        
        return sarif_result
    
    def get_cwe_id(self) -> Optional[str]:
        """
        Extrait l'ID CWE des métadonnées.
        
        Returns:
            ID CWE si présent, sinon None
        """
        return self.metadata.get("cwe")
    
    def get_owasp_category(self) -> Optional[str]:
        """
        Extrait la catégorie OWASP des métadonnées.
        
        Returns:
            Catégorie OWASP si présente, sinon None
        """
        return self.metadata.get("owasp")
    
    def __str__(self) -> str:
        """Représentation string du finding."""
        return (f"{self.severity.value}: {self.rule_id} at "
                f"{self.location.file_path}:{self.location.line}:{self.location.column}")
    
    def __repr__(self) -> str:
        """Représentation pour debug."""
        return (f"Finding(rule_id='{self.rule_id}', severity={self.severity}, "
                f"location={self.location.file_path}:{self.location.line})")