#include "firewall_tree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_usage(const char *program) {
    printf("Uso:\n");
    printf("  %s --blocked <arquivo> --input <arquivo>\n", program);
    printf("  %s --blocked <arquivo> --add <ip>\n", program);
    printf("  %s --blocked <arquivo> --remove <ip>\n", program);
    printf("  %s --blocked <arquivo> --query <ip>\n", program);
}

int main(int argc, char **argv) {
    const char *blocked_path = NULL;
    const char *input_path = NULL;
    const char *ip_value = NULL;
    enum {
        ACTION_NONE,
        ACTION_ADD,
        ACTION_REMOVE,
        ACTION_QUERY,
        ACTION_CHECK_FILE
    } action = ACTION_NONE;

    FirewallDatabase db;
    int loaded_count = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--blocked") == 0 && i + 1 < argc) {
            blocked_path = argv[++i];
        } else if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
            input_path = argv[++i];
            action = ACTION_CHECK_FILE;
        } else if (strcmp(argv[i], "--add") == 0 && i + 1 < argc) {
            ip_value = argv[++i];
            action = ACTION_ADD;
        } else if (strcmp(argv[i], "--remove") == 0 && i + 1 < argc) {
            ip_value = argv[++i];
            action = ACTION_REMOVE;
        } else if (strcmp(argv[i], "--query") == 0 && i + 1 < argc) {
            ip_value = argv[++i];
            action = ACTION_QUERY;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "Argumento inválido: %s\n", argv[i]);
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (blocked_path == NULL) {
        fprintf(stderr, "Informe o caminho do arquivo de IPs bloqueados com --blocked.\n");
        return EXIT_FAILURE;
    }

    if (!firewall_db_init(&db, blocked_path, &loaded_count)) {
        fprintf(stderr, "Falha ao inicializar o banco interno de IPs bloqueados.\n");
        return EXIT_FAILURE;
    }

    printf("Banco de IPs carregado: %s (%d IPs).\n", blocked_path, loaded_count);

    switch (action) {
        case ACTION_ADD:
            {
                clock_t start = clock();
                if (ip_value == NULL || !firewall_db_add(&db, ip_value)) {
                    fprintf(stderr, "Falha ao inserir o IP %s.\n", ip_value != NULL ? ip_value : "<nulo>");
                    firewall_db_free(&db);
                    return EXIT_FAILURE;
                }
                clock_t end = clock();
                double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
                printf("IP %s inserido com sucesso.\n", ip_value);
                printf("Tempo de execucao: %.6f segundos\n", elapsed);
            }
            break;

        case ACTION_REMOVE:
            {
                clock_t start = clock();
                if (ip_value == NULL || !firewall_db_remove(&db, ip_value)) {
                    fprintf(stderr, "Falha ao remover o IP %s.\n", ip_value != NULL ? ip_value : "<nulo>");
                    firewall_db_free(&db);
                    return EXIT_FAILURE;
                }
                clock_t end = clock();
                double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
                printf("IP %s removido com sucesso.\n", ip_value);
                printf("Tempo de execução: %.6f segundos\n", elapsed);
            }
            break;

        case ACTION_QUERY:
            {
                clock_t start = clock();
                if (ip_value == NULL) {
                    fprintf(stderr, "Informe um IP para consultar.\n");
                    firewall_db_free(&db);
                    return EXIT_FAILURE;
                }
                bool result = firewall_db_contains(&db, ip_value);
                clock_t end = clock();
                double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
                printf("%s -> %s\n", ip_value, result ? "BLOCKED" : "ALLOWED");
                printf("Tempo de execução: %.6f segundos\n", elapsed);
            }
            break;

        case ACTION_CHECK_FILE:
            if (input_path == NULL) {
                fprintf(stderr, "Informe um arquivo de entrada com --input.\n");
                firewall_db_free(&db);
                return EXIT_FAILURE;
            }
            {
                clock_t start = clock();
                if (!firewall_db_check_file(&db, input_path)) {
                    fprintf(stderr, "Não foi possível abrir o arquivo %s.\n", input_path);
                    firewall_db_free(&db);
                    return EXIT_FAILURE;
                }
                clock_t end = clock();
                double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
                printf("\nTempo de execução: %.6f segundos\n", elapsed);
            }
            break;

        case ACTION_NONE:
            printf("Nenhuma operação específica solicitada. O banco interno foi carregado.\n");
            break;
    }

    firewall_db_free(&db);
    return EXIT_SUCCESS;
}
