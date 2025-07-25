/*
 * Fichier d'exemple avec vulnérabilités pour démonstration Cerberus-SAST
 * 
 * Ce fichier contient intentionnellement plusieurs vulnérabilités de sécurité
 * détectables par les règles de Cerberus-SAST.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_gets_example() {
    char buffer[64];
    
    printf("Entrez votre nom: ");
    
    // VULNÉRABILITÉ: gets() est dangereuse (buffer overflow)
    // Règle détectée: c-buffer-overflow-gets
    gets(buffer);
    
    printf("Bonjour %s!\n", buffer);
}

void vulnerable_strcpy_example(char* user_input) {
    char destination[32];
    
    // VULNÉRABILITÉ: strcpy() sans vérification de taille
    // Règle détectée: c-buffer-overflow-strcpy
    strcpy(destination, user_input);
    
    printf("Copié: %s\n", destination);
}

void vulnerable_sprintf_example(int id, char* name) {
    char output[50];
    
    // VULNÉRABILITÉ: sprintf() peut déborder
    // Règle détectée: c-buffer-overflow-sprintf
    sprintf(output, "User ID: %d, Name: %s, Status: Active", id, name);
    
    printf("%s\n", output);
}

void vulnerable_format_string(char* user_controlled) {
    // VULNÉRABILITÉ: Format string contrôlé par l'utilisateur
    // Règle détectée: c-format-string-bug
    printf(user_controlled);
    printf("\n");
}

// Fonction sécurisée pour comparaison
void secure_example() {
    char buffer[64];
    
    printf("Version sécurisée - Entrez votre nom: ");
    
    // Utilisation sécurisée de fgets
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Supprimer le newline si présent
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\n') {
            buffer[len-1] = '\0';
        }
        printf("Bonjour %s (version sécurisée)!\n", buffer);
    }
}

int main(int argc, char* argv[]) {
    printf("=== Démonstration Cerberus-SAST ===\n");
    printf("Ce programme contient intentionnellement des vulnérabilités.\n\n");
    
    // Exécution des fonctions vulnérables
    vulnerable_gets_example();
    
    if (argc > 1) {
        vulnerable_strcpy_example(argv[1]);
        vulnerable_sprintf_example(123, argv[1]);
        vulnerable_format_string(argv[1]);
    }
    
    secure_example();
    
    return 0;
}