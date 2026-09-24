/* Negative control: bounded C string handling. Nothing here should be flagged. */
#include <stdio.h>
#include <string.h>

void copy_username(const char *input) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s", input);
    puts(buffer);
}

void read_line(void) {
    char line[128];
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return;
    }
    puts(line);
}

void safe_copy(const char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

/* Identifiers that merely CONTAIN a dangerous name, to pin down the word-boundary
   anchors used by the C rules. The wrapper below must not be reported, and the
   readiness helper must not be mistaken for a shell call. */

// Regression guard for whole-line comment skipping. The two calls spelled out
// literally below are strcpy( and system(, and a comment of this shape must stay
// silent. Only WHOLE-LINE comments get that guarantee, so block comments and
// trailing comments remain a documented limitation.
void my_strcpy_wrapper(const char *src, char *dst, size_t n) {
    strncpy(dst, src, n);
}

int system_utils_ready(void) {
    return 1;
}
