#ifndef FIREWALL_TREE_H
#define FIREWALL_TREE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct FirewallNode FirewallNode;

typedef struct {
    FirewallNode *root;
} FirewallTree;

typedef struct {
    FirewallTree tree;
    char *path;
} FirewallDatabase;

bool firewall_tree_init(FirewallTree *tree);
void firewall_tree_free(FirewallTree *tree);

bool firewall_tree_insert(FirewallTree *tree, const char *ip);
bool firewall_tree_remove(FirewallTree *tree, const char *ip);
bool firewall_tree_contains(const FirewallTree *tree, const char *ip);

bool firewall_tree_load_from_file(FirewallTree *tree, const char *path, int *loaded_count);
bool firewall_tree_save_to_file(const FirewallTree *tree, const char *path);
bool firewall_tree_check_file(const FirewallTree *tree, const char *path);

bool firewall_db_init(FirewallDatabase *db, const char *path, int *loaded_count);
void firewall_db_free(FirewallDatabase *db);
bool firewall_db_add(FirewallDatabase *db, const char *ip);
bool firewall_db_remove(FirewallDatabase *db, const char *ip);
bool firewall_db_contains(const FirewallDatabase *db, const char *ip);
bool firewall_db_check_file(const FirewallDatabase *db, const char *path);

#endif
