#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "debug.h"
#include "domain_tree.h"

domain_tree_char_node_ptr domain_tree_create_char_node(domain_tree_char_node_ptr parent)
{
	domain_tree_char_node_ptr node = malloc(sizeof(domain_tree_char_node));
	if (!node) {
		int errnum = errno;
		debug_print("%s", strerror(errnum));
		exit(EXIT_FAILURE);
		// IF NOT EXIT RETURN NULL && MUST CHECK IN CALLER
		// return NULL;
	}
	if (parent) {
		parent->is_leaf = false;
		parent->n_children++;
	}
	node->parent = parent;
	node->is_str_end = false;
	node->is_leaf = true;
	node->n_children = 0;
	for (int i = 0; i < DOMAIN_CHAR_POOL_SIZE; i++)
		node->children[i] = NULL;
	return node;
}

int domain_tree_insert_fixed_len(domain_tree_char_node_ptr root, char *domain, size_t len_remain)
{
	domain_tree_char_node_ptr cur_root = root;
	if (len_remain > 0) {
		for (int i = len_remain - 1; i >= 0; i--) {
			if (cur_root->children[DOMAIN_CHILD_CHAR_TO_INDEX(domain[i])] == NULL) {
				cur_root->children[DOMAIN_CHILD_CHAR_TO_INDEX(domain[i])] = domain_tree_create_char_node(cur_root);
			}
			cur_root = cur_root->children[DOMAIN_CHILD_CHAR_TO_INDEX(domain[i])];
			// If str end
			if (i == 0)
				cur_root->is_str_end = true;
		}
		return RETURN_SUCCESS;
	}
	else
		return RETURN_FAILURE;
}

int domain_tree_insert(domain_tree_char_node_ptr root, char *domain)
{
	size_t len_remain = strlen(domain);
	return domain_tree_insert_fixed_len(root, domain, len_remain);
}

domain_tree_char_node_ptr domain_tree_traverse_fixed_len(domain_tree_char_node_ptr root, char *domain, size_t len_remain)
{
	domain_tree_char_node_ptr cur_root = root;
	if (len_remain > 0) {
		for (int i = len_remain - 1; i >= 0; i--) {
			// If the child node is null
			if (cur_root->children[DOMAIN_CHILD_CHAR_TO_INDEX(domain[i])] == NULL)
				return NULL;
			cur_root = cur_root->children[DOMAIN_CHILD_CHAR_TO_INDEX(domain[i])];
		}
		// Return the last node
		return cur_root;
	}
	else
		return NULL;
}

domain_tree_char_node_ptr domain_tree_traverse(domain_tree_char_node_ptr root, char *domain)
{
	size_t len_remain = strlen(domain);
	return domain_tree_traverse_fixed_len(root, domain, len_remain);
}

domain_tree_char_node_ptr
domain_tree_traverse_domain_mode_fixed_len(domain_tree_char_node_ptr root, char *domain, size_t len)
{
	domain_tree_char_node_ptr cur_root = root;
	if (len > 0) {
		for (int i = len - 1; i >= 0; i--) {
			if (domain[i] == '.'){
				if (cur_root->is_str_end)
					return cur_root;
			}
			// If the child node is null
			if (cur_root->children[DOMAIN_CHILD_CHAR_TO_INDEX(domain[i])] == NULL)
				return NULL;
			cur_root = cur_root->children[DOMAIN_CHILD_CHAR_TO_INDEX(domain[i])];
		}
		// Return the last node iff exact match
		if (cur_root->is_str_end)
			return cur_root;
		else return NULL;
	}
	else
		return NULL;
}

domain_tree_char_node_ptr
domain_tree_traverse_domain_mode(domain_tree_char_node_ptr root, char *domain)
{
	size_t len = strlen(domain);
	return domain_tree_traverse_domain_mode_fixed_len(root, domain, len);
}

bool domain_tree_search_exact(domain_tree_char_node *root, char *domain)
{
	domain_tree_char_node_ptr head = domain_tree_traverse(root, domain);
	if (head == NULL) return false;
	return head->is_str_end;
}

bool domain_tree_search_substr(domain_tree_char_node_ptr root, char *domain)
{
	domain_tree_char_node_ptr head = domain_tree_traverse(root, domain);
	if (head == NULL) return false;
	return true;
}

bool domain_tree_search_domain(domain_tree_char_node_ptr root, char *domain)
{
	domain_tree_char_node_ptr head = domain_tree_traverse_domain_mode(root, domain);
	return (head != NULL);
}

int domain_tree_delete_children(domain_tree_char_node_ptr root)
{
	if (root->is_leaf)
		return RETURN_FAILURE;
	else {
		for (int i = 0; i < DOMAIN_CHAR_POOL_SIZE; i++) {
			if (root->children[i]) {
				if (!root->children[i]->is_leaf)
					domain_tree_delete_children(root->children[i]);
				free(root->children[i]);
				root->children[i] = NULL;
			}
		}
		root->is_leaf = true;
		root->n_children = 0;
		return RETURN_SUCCESS;
	}
}

int domain_tree_delete_child(domain_tree_char_node_ptr root, size_t ind)
{
	if (root->is_leaf) {
		return RETURN_FAILURE;
	}
	else {
		if (root->children[ind]) {
			domain_tree_delete_children(root->children[ind]);
			free(root->children[ind]);
			root->children[ind] = NULL;
			root->n_children--;
			if (root->n_children <= 0)
				root->is_leaf = true;
			return RETURN_SUCCESS;
		}
		return RETURN_FAILURE;
	}
}

int domain_tree_delete_match_fixed_len(domain_tree_char_node_ptr root, char *domain, size_t len_remain)
{
	// Implement its own traverse with delete
	// Look ahead see if next child available, this func never reduce len_remain below 1 so if match there should be a child
	size_t next_child_ind = DOMAIN_CHILD_CHAR_TO_INDEX(domain[len_remain - 1]);
	domain_tree_char_node_ptr next_child_node = root->children[next_child_ind];
	if (next_child_node == NULL) {
		// Err not found, do not delete this node
		return RETURN_FAILURE;
	}

	if (len_remain > 1) {
		if (domain_tree_delete_match_fixed_len(next_child_node, domain, len_remain - 1) == RETURN_SUCCESS) {
			// CHILD is leaf & marked for deletion
			domain_tree_delete_child(root, next_child_ind);
			// If this node is now leaf, also mark for delete
			if (root->is_leaf)
				return RETURN_SUCCESS;
		}
		return RETURN_FAILURE;
	}
	else {
		if (next_child_node->is_str_end) {
			// EXACT MATCH
			// Delete child & its children
			domain_tree_delete_child(root, next_child_ind);
			// If there are no other children mark this node for delete
			if(root->is_leaf)
				return RETURN_SUCCESS;
			else
				return RETURN_FAILURE;
		}
		// NOT EXACT MATCH, JUST A SUBSTR
		return RETURN_FAILURE;
	}
}

void domain_tree_delete_match(domain_tree_char_node_ptr root, char *domain)
{
	size_t len_remain = strlen(domain);
	domain_tree_delete_match_fixed_len(root, domain, len_remain);
}

char domain_print_buffer[DOMAIN_PRINT_BUFF_SIZE];

void domain_print(size_t ind)
{
	for (int i = ind; i >= 0; i--) {
		debug_print("%c\n", domain_print_buffer[i]);
	}
	debug_print("%s", "\n");
}

void domain_tree_dump(domain_tree_char_node_ptr root, size_t ind)
{
	for (int i = 0; i < DOMAIN_CHAR_POOL_SIZE; i++) {
		if (root->children[i]) {
			domain_print_buffer[ind] = DOMAIN_CHILD_INDEX_TO_CHAR(i);
			if (root->children[i]->is_str_end)
				domain_print(ind);
			if (!(root->children[i]->is_leaf) && ind < DOMAIN_PRINT_BUFF_SIZE - 1)
				domain_tree_dump(root->children[i], ind + 1);
		}
	}
}
