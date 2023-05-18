#ifndef DOMAIN_TREE_H
#define DOMAIN_TREE_H

#include <stdbool.h>
#include "common.h"
// TODO: SOHULD THIS NEED TO ME MODIFIED BY A THREAD, ADD LOCK
// FOR PATTERN MATCHING SWITCH TO SUFFIX TREE LATER

// Takes visible ASCII only, from 33 to 126
// From ASCII to index -33 
#define DOMAIN_CHAR_POOL_SIZE 94
#define DOMAIN_CHILD_CHAR_TO_INDEX(x) x-33
#define DOMAIN_CHILD_INDEX_TO_CHAR(x) x+33

//#define RETURN_SUCCESS 0
//#define RETURN_FAILURE 1

// Represents a node in the tree
typedef struct domain_tree_char_node_ 
{
	// For reverse traversing, root node parent is always 0
	struct domain_tree_char_node_ *parent;
	struct domain_tree_char_node_ **entry_in_parent;
	// If true then a substring in the tree is ended with this node. NOT indicate child availability
	// E.G:
	// 	1. add com.vn
	// 	2. add test.com.vn
	// Then when traverse, this bool is true for both end node of com.vn and test.com.vn
	// indicate that this domain is added deliberately, not substring artefact
	// root node's is_str_end always false
	bool is_str_end;
	// All possible children, using char value as index
	struct domain_tree_char_node_ *children[DOMAIN_CHAR_POOL_SIZE];
	bool is_leaf;
	// Number of children allocated
	unsigned int n_children;
} domain_tree_char_node;

typedef domain_tree_char_node *domain_tree_char_node_ptr;

// Return a new node, call with parent = NULL to create a root node
domain_tree_char_node_ptr domain_tree_create_char_node(domain_tree_char_node_ptr parent);
// Insert new domain with known length
int domain_tree_insert_fixed_len(domain_tree_char_node_ptr root, char *domain, size_t len);
// Insert new domain, null terminated
int domain_tree_insert(domain_tree_char_node_ptr root, char *domain);
// Traverse tree using a domain, return last node is there are any, else NULL
domain_tree_char_node_ptr domain_tree_traverse_fixed_len(domain_tree_char_node_ptr root, char *domain, size_t len);
// Traverse tree using a domain, return last node is there are any, else NULL
domain_tree_char_node_ptr domain_tree_traverse(domain_tree_char_node_ptr root, char *domain);
// Traverse but stopped at first subdomain exact match, separated by '.', else if no no exact match return 0
domain_tree_char_node_ptr 
domain_tree_traverse_domain_mode_fixed_len(domain_tree_char_node_ptr root, char *domain, size_t len);
// Traverse but stopped at first subdomain exact match, separated by '.', else if no no exact match return 0
domain_tree_char_node_ptr domain_tree_traverse_domain_mode(domain_tree_char_node_ptr root, char *domain);
// Search stored domains for matching record return true if there is any string end exactly where search string end
bool domain_tree_search_exact(domain_tree_char_node_ptr root, char *domain);
// Search stored domains, return true if there are full match or search string is substr of other str
bool domain_tree_search_substr(domain_tree_char_node_ptr root, char *domain);
// For a given domain a.b.c.d. a, b, c, d are strings with arbitrary length do
// comp(d)
// comp(c.d)
// comp(b.c.d)
// comp(a.b.c.d)
// If any match then return true, this ensure if 1 domain is blocked any subdomain will not pass
bool domain_tree_search_domain(domain_tree_char_node_ptr root, char *domain);
// For a given root node, delete all its children
int domain_tree_delete_children(domain_tree_char_node_ptr root);
// For a given root node, delete child @ selected index & its children
int domain_tree_delete_child(domain_tree_char_node_ptr root, size_t ind);
// Remove a given string from the tree iff there is a match
// If a given str match and is a part of larger str set, all larger str set will be removed as well
// E.G:
// 	1. add com.vn
//  2. add test.com.vn
// domain_tree_delete_match(, "vn") won't work because vn is not explicitly added
// domain_tree_delete_match(, "com.vn") will delete both com.vn and test.com.vn
// domain_tree_delete_match(, "test.com.vn") only delete test.com.vn
// RETURN VALUE OF THIS FUNC DOES NOT REPRESENT WHETHER DELETION SUCCEEDED OR NOT, JUST USED FOR DELETION TAGGING
int domain_tree_delete_match_fixed_len(domain_tree_char_node_ptr root, char *domain, size_t len_remain);
// Called domain_tree_delete_match_fixed_len
void domain_tree_delete_match(domain_tree_char_node_ptr root, char *domain);

// For domain dump function only
#define DOMAIN_PRINT_BUFF_SIZE 100
extern char domain_print_buffer[DOMAIN_PRINT_BUFF_SIZE];
// Print buffer in reverse started from ind
void domain_print(size_t ind);
// Dump all explicitly stored domains from a given root to stderr
// ind == current index into buffer, 0 for start
void domain_tree_dump(domain_tree_char_node_ptr root, size_t ind);

#endif
