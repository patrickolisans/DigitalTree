#include "firewall_tree.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IPV4_BITS 32
#define BRANCHING_FACTOR 4
#define SYMBOLS_PER_IP (IPV4_BITS / 2)

typedef struct FirewallNode {
    struct FirewallNode *children[BRANCHING_FACTOR];
    bool terminal;
} FirewallNode;

static void free_node(FirewallNode *node) {
    if (!node) {
        return;
    }

    for (int i = 0; i < BRANCHING_FACTOR; ++i) {
        free_node(node->children[i]);
    }

    free(node);
}

static char *duplicate_string(const char *text) {
    size_t length = strlen(text) + 1;
    char *copy = (char *)malloc(length);

    if (copy != NULL) {
        memcpy(copy, text, length);
    }

    return copy;
}

static char *trim_whitespace(char *text) {
    char *end;

    while (*text != '\0' && isspace((unsigned char)*text)) {
        ++text;
    }

    if (*text == '\0') {
        return text;
    }

    end = text + strlen(text);
    while (end > text && isspace((unsigned char)*(end - 1))) {
        --end;
    }

    *end = '\0';
    return text;
}

static bool parse_ipv4(const char *ip, uint32_t *value) {
    unsigned int octets[4];
    int matched = sscanf(ip, "%u.%u.%u.%u", &octets[0], &octets[1], &octets[2], &octets[3]);

    if (matched != 4) {
        return false;
    }

    for (int i = 0; i < 4; ++i) {
        if (octets[i] > 255U) {
            return false;
        }
    }

    *value = ((uint32_t)octets[0] << 24) |
             ((uint32_t)octets[1] << 16) |
             ((uint32_t)octets[2] << 8) |
             (uint32_t)octets[3];

    return true;
}

static void ipv4_to_symbols(uint32_t value, uint8_t symbols[SYMBOLS_PER_IP]) {
    for (int i = 0; i < SYMBOLS_PER_IP; ++i) {
        symbols[i] = (uint8_t)((value >> (30 - 2 * i)) & 0x3U);
    }
}

static void format_ipv4(uint32_t value, char *buffer, size_t size) {
    snprintf(buffer, size, "%u.%u.%u.%u",
             (unsigned int)((value >> 24) & 0xFFU),
             (unsigned int)((value >> 16) & 0xFFU),
             (unsigned int)((value >> 8) & 0xFFU),
             (unsigned int)(value & 0xFFU));
}

static bool has_children(const FirewallNode *node) {
    for (int i = 0; i < BRANCHING_FACTOR; ++i) {
        if (node->children[i] != NULL) {
            return true;
        }
    }
    return false;
}

static void insert_symbols(FirewallNode *node, const uint8_t *symbols, int depth) {
    if (depth == SYMBOLS_PER_IP) {
        node->terminal = true;
        return;
    }

    int symbol = symbols[depth];
    if (node->children[symbol] == NULL) {
        node->children[symbol] = (FirewallNode *)calloc(1, sizeof(FirewallNode));
        if (node->children[symbol] == NULL) {
            fprintf(stderr, "Erro ao alocar nó da árvore.\n");
            exit(EXIT_FAILURE);
        }
    }

    insert_symbols(node->children[symbol], symbols, depth + 1);
}

static bool contains_symbols(const FirewallNode *node, const uint8_t *symbols, int depth) {
    if (node == NULL) {
        return false;
    }

    if (depth == SYMBOLS_PER_IP) {
        return node->terminal;
    }

    return contains_symbols(node->children[symbols[depth]], symbols, depth + 1);
}

static bool remove_symbols(FirewallNode *node, const uint8_t *symbols, int depth) {
    if (node == NULL) {
        return false;
    }

    if (depth == SYMBOLS_PER_IP) {
        if (!node->terminal) {
            return false;
        }

        node->terminal = false;
        return true;
    }

    int symbol = symbols[depth];
    if (node->children[symbol] == NULL) {
        return false;
    }

    bool removed = remove_symbols(node->children[symbol], symbols, depth + 1);
    if (!removed) {
        return false;
    }

    if (!node->children[symbol]->terminal && !has_children(node->children[symbol])) {
        free_node(node->children[symbol]);
        node->children[symbol] = NULL;
    }

    return true;
}

static void collect_ips(FirewallNode *node, uint32_t prefix, int depth, FILE *file) {
    if (node == NULL) {
        return;
    }

    if (depth == SYMBOLS_PER_IP) {
        if (node->terminal) {
            char buffer[32];
            format_ipv4(prefix, buffer, sizeof(buffer));
            fprintf(file, "%s\n", buffer);
        }
        return;
    }

    for (int symbol = 0; symbol < BRANCHING_FACTOR; ++symbol) {
        if (node->children[symbol] != NULL) {
            uint32_t next_prefix = prefix | ((uint32_t)symbol << (30 - 2 * depth));
            collect_ips(node->children[symbol], next_prefix, depth + 1, file);
        }
    }
}

bool firewall_tree_init(FirewallTree *tree) {
    if (tree == NULL) {
        return false;
    }

    tree->root = (FirewallNode *)calloc(1, sizeof(FirewallNode));
    return tree->root != NULL;
}

void firewall_tree_free(FirewallTree *tree) {
    if (tree == NULL) {
        return;
    }

    free_node(tree->root);
    tree->root = NULL;
}

bool firewall_tree_insert(FirewallTree *tree, const char *ip) {
    uint32_t value;
    uint8_t symbols[SYMBOLS_PER_IP];

    if (tree == NULL || ip == NULL || !parse_ipv4(ip, &value)) {
        return false;
    }

    ipv4_to_symbols(value, symbols);
    insert_symbols(tree->root, symbols, 0);
    return true;
}

bool firewall_tree_remove(FirewallTree *tree, const char *ip) {
    uint32_t value;
    uint8_t symbols[SYMBOLS_PER_IP];

    if (tree == NULL || ip == NULL || !parse_ipv4(ip, &value)) {
        return false;
    }

    ipv4_to_symbols(value, symbols);
    return remove_symbols(tree->root, symbols, 0);
}

bool firewall_tree_contains(const FirewallTree *tree, const char *ip) {
    uint32_t value;
    uint8_t symbols[SYMBOLS_PER_IP];

    if (tree == NULL || ip == NULL || !parse_ipv4(ip, &value)) {
        return false;
    }

    ipv4_to_symbols(value, symbols);
    return contains_symbols(tree->root, symbols, 0);
}

bool firewall_tree_load_from_file(FirewallTree *tree, const char *path, int *loaded_count) {
    FILE *file = fopen(path, "r");
    char line[64];
    int count = 0;

    if (tree == NULL || path == NULL) {
        return false;
    }

    if (file == NULL) {
        if (errno == ENOENT) {
            FILE *new_file = fopen(path, "w");
            if (new_file != NULL) {
                fclose(new_file);
            }
            if (loaded_count != NULL) {
                *loaded_count = 0;
            }
            return true;
        }
        return false;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *ip = trim_whitespace(line);
        if (*ip == '\0') {
            continue;
        }

        if (firewall_tree_insert(tree, ip)) {
            ++count;
        }
    }

    fclose(file);

    if (loaded_count != NULL) {
        *loaded_count = count;
    }

    return true;
}

bool firewall_tree_save_to_file(const FirewallTree *tree, const char *path) {
    FILE *file = fopen(path, "w");

    if (tree == NULL || path == NULL || file == NULL) {
        return false;
    }

    collect_ips(tree->root, 0, 0, file);
    fclose(file);
    return true;
}

bool firewall_tree_check_file(const FirewallTree *tree, const char *path) {
    FILE *file = fopen(path, "r");
    char line[64];
    int checked = 0;
    int blocked = 0;

    if (tree == NULL || path == NULL || file == NULL) {
        return false;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *ip = trim_whitespace(line);
        if (*ip == '\0') {
            continue;
        }

        ++checked;
        if (firewall_tree_contains(tree, ip)) {
            ++blocked;
            printf("%s -> BLOCKED\n", ip);
        }
    }

    fclose(file);
    printf("Resumo: %d IPs verificados, %d bloqueados.\n", checked, blocked);
    return true;
}

bool firewall_db_init(FirewallDatabase *db, const char *path, int *loaded_count) {
    if (db == NULL || path == NULL) {
        return false;
    }

    memset(db, 0, sizeof(*db));

    if (!firewall_tree_init(&db->tree)) {
        return false;
    }

    db->path = duplicate_string(path);
    if (db->path == NULL) {
        firewall_tree_free(&db->tree);
        return false;
    }

    return firewall_tree_load_from_file(&db->tree, db->path, loaded_count);
}

void firewall_db_free(FirewallDatabase *db) {
    if (db == NULL) {
        return;
    }

    free(db->path);
    db->path = NULL;
    firewall_tree_free(&db->tree);
}

bool firewall_db_add(FirewallDatabase *db, const char *ip) {
    if (db == NULL || ip == NULL) {
        return false;
    }

    if (!firewall_tree_insert(&db->tree, ip)) {
        return false;
    }

    return firewall_tree_save_to_file(&db->tree, db->path);
}

bool firewall_db_remove(FirewallDatabase *db, const char *ip) {
    if (db == NULL || ip == NULL) {
        return false;
    }

    if (!firewall_tree_remove(&db->tree, ip)) {
        return false;
    }

    return firewall_tree_save_to_file(&db->tree, db->path);
}

bool firewall_db_contains(const FirewallDatabase *db, const char *ip) {
    if (db == NULL || ip == NULL) {
        return false;
    }

    return firewall_tree_contains(&db->tree, ip);
}

bool firewall_db_check_file(const FirewallDatabase *db, const char *path) {
    if (db == NULL || path == NULL) {
        return false;
    }

    return firewall_tree_check_file(&db->tree, path);
}
