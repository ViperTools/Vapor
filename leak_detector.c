#include <stdlib.h>
#include <stdio.h>
const int ENABLE_LOGGING = 0;

typedef struct AddressInfo {
	void* ptr;
	const char* file;
	int line;
	const char* func;
} AddressInfo;

typedef struct ListNode {
	void* data;
	struct ListNode* next;
} ListNode;

ListNode* list = 0;

void addAddress(void* ptr, const char* file, int line, const char* func) {
	ListNode* node = malloc(sizeof(ListNode));
	AddressInfo* info = malloc(sizeof(AddressInfo));
	info->ptr = ptr;
	info->file = file;
	info->line = line;
	info->func = func;

	node->data = info;

	if (!list) {
		list = node;
		node->next = 0;
	}
	else {
		node->next = list;
		list = node;
	}
}

int removeAddress(void* ptr) {
	ListNode* node = list;
	ListNode* prev = 0;

	while (node) {
		AddressInfo* info = (AddressInfo*)node->data;

		if (info->ptr == ptr) {
			if (!prev) {
				list = node->next;
			}
			else {
				prev->next = node->next;
			}

			free(node->data);
			free(node);
			return 1;
		}

		prev = node;
		node = node->next;
	}

	return 0;
}

int countAddresses() {
	ListNode* node = list;
	int count = 0;

	while (node) {
		++count;
		node = node->next;
	}

	return count;
}

void leak_detector_print_addresses() {
	ListNode* node = list;
	printf("Addresses:\n");

	while (node) {
		AddressInfo* info = (AddressInfo*)node->data;
		printf("\033[36mfile: %s \033[33mline: %i \033[35mfunction: %s \033[0m%p\n", info->file, info->line, info->func, info->ptr);
		node = node->next;
	}
}

void leak_detector_print_num_addresses() {
	int count = countAddresses();

	if (!count) {
		printf("\033[32mnumber of allocated addresses: %d\033[0m\n", count);
	}
	else {
		printf("\033[31mnumber of allocated addresses: %d\033[0m\n", count);
	}
}

void* leak_detector_malloc(size_t size, const char* file, int line, const char* func) {
	void* p = malloc(size);

	if (ENABLE_LOGGING) {
		printf("malloc: \033[36mfile: %s \033[33mline: %i \033[35mfunction: %s \033[0m%p[%li]\n", file, line, func, p, size);
	}

	addAddress(p, file, line, func);

	return p;
}

void* leak_detector_calloc(size_t count, size_t size, const char* file, int line, const char* func) {
	void* p = calloc(count, size);

	if (ENABLE_LOGGING) {
		printf("calloc: \033[36mfile: %s \033[33mline: %i \033[35mfunction: %s \033[0m%p[%li]\n", file, line, func, p, count * size);
	}

	addAddress(p, file, line, func);

	return p;
}

void* leak_detector_realloc(void* p, size_t size, const char* file, int line, const char* func) {
	void* new = realloc(p, size);

	if (ENABLE_LOGGING) {
		printf("realloc: \033[36mfile: %s \033[33mline: %i \033[35mfunction: %s \033[0m%p -> %p[%li]\n", file, line, func, p, new, size);
	}

	if (!removeAddress(p)) {
		printf("\033[31minvalid realloc\033[0m\n", file, line, func, p, new, size);
	}

	addAddress(new, file, line, func);

	return new;
}

char* leak_detector_strdup(const char* str, const char* file, int line, const char* func) {
	char* p = strdup(str);

	addAddress(p, file, line, func);

	return p;
}

void leak_detector_free(void* p, const char* file, int line, const char* func) {
	free(p);

	removeAddress(p);

	if (ENABLE_LOGGING) {
		printf("free: \033[36mfile: %s \033[33mline: %i \033[35mfunction: %s \033[0m%p\n", file, line, func, p);
		leak_detector_print_num_addresses();
	}
}