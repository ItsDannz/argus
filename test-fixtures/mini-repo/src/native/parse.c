/* Fixture: the unsafe C functions, one per line, each in a plausible context.
 *
 * Four lines should be flagged: strcpy and sprintf are High, gets and system are
 * Critical. The buffer sizes are deliberate — this is what the code looks like
 * before somebody decides the bounds check is not worth the diff.
 *
 * Note the shape of this comment. It names the functions without writing them
 * the way they are called, because a block comment is still source: the rules
 * match on what a line says, and only WHOLE-LINE `//` comments are skipped. A
 * comment that spelled the calls out would be reported, correctly and uselessly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_header(const char *input) {
    char name[64];
    strcpy(name, input);
    printf("name: %s\n", name);
}

void read_command(void) {
    char line[256];
    gets(line);
    system(line);
}

void build_path(const char *dir) {
    char path[128];
    sprintf(path, "/var/data/%s", dir);
    puts(path);
}
