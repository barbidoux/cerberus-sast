#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Exemple de code vulnérable pour tester Cerberus-SAST

void vulnerable_strcpy(char *input) {
    char buffer[64];
    // VULNÉRABILITÉ: strcpy ne vérifie pas la taille du buffer
    strcpy(buffer, input);  // c-buffer-overflow-strcpy
    printf("Buffer: %s\n", buffer);
}

void vulnerable_gets() {
    char username[32];
    printf("Entrez votre nom: ");
    // VULNÉRABILITÉ: gets() est dangereuse et dépréciée
    gets(username);  // c-buffer-overflow-gets
    printf("Bonjour %s!\n", username);
}

void vulnerable_sprintf(int id, char *name) {
    char output[100];
    // VULNÉRABILITÉ: sprintf peut causer un buffer overflow
    sprintf(output, "User ID: %d, Name: %s", id, name);  // c-buffer-overflow-sprintf
    printf("%s\n", output);
}

void format_string_bug(char *user_input) {
    // VULNÉRABILITÉ: Format string contrôlé par l'utilisateur
    printf(user_input);  // c-format-string-bug
}

// Exemple de code sécurisé
void secure_string_copy(char *input) {
    char buffer[64];
    // Utilisation sécurisée de strncpy
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Assurer la terminaison
    printf("Buffer sécurisé: %s\n", buffer);
}

void secure_input() {
    char username[32];
    printf("Entrez votre nom: ");
    // Utilisation sécurisée de fgets
    if (fgets(username, sizeof(username), stdin) != NULL) {
        // Supprimer le newline si présent
        size_t len = strlen(username);
        if (len > 0 && username[len-1] == '\n') {
            username[len-1] = '\0';
        }
        printf("Bonjour %s!\n", username);
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_strcpy(argv[1]);
        format_string_bug(argv[1]);
    }
    
    vulnerable_gets();
    vulnerable_sprintf(123, "test");
    
    return 0;
}