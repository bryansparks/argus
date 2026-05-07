#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* VULNERABILITY: buffer overflow — fixed buffer, no bounds check on user input */
void process_name(const char *input) {
    char buf[64];
    strcpy(buf, input);  /* unsafe: overflows if input > 63 bytes */
    printf("Name: %s\n", buf);
}

/* VULNERABILITY: format string injection — user-controlled format arg */
void log_message(const char *msg) {
    printf(msg);  /* should be printf("%s", msg) */
}

/* VULNERABILITY: integer overflow before malloc
   If count is large, count * sizeof(int) wraps on 32-bit size_t,
   producing a tiny allocation followed by an out-of-bounds write. */
void allocate_items(unsigned int count) {
    int *arr = (int *)malloc(count * sizeof(int));
    if (arr == NULL) return;
    for (unsigned int i = 0; i < count; i++) {
        arr[i] = (int)i;
    }
    free(arr);
}

/* VULNERABILITY: use-after-free — buf is accessed after free() */
void process_data(void) {
    char *buf = (char *)malloc(100);
    if (!buf) return;
    strcpy(buf, "sensitive data");
    free(buf);
    printf("After free: %s\n", buf);  /* undefined behaviour */
}

/* VULNERABILITY: double-free on error path */
void double_free_example(int error) {
    char *p = (char *)malloc(64);
    if (!p) return;
    if (error) {
        free(p);
    }
    free(p);  /* freed twice when error != 0 */
}
