/* Fixture: unsafe C functions. Four lines here should be flagged. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void copy_username(const char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("%s\n", buffer);
}

void read_line(void) {
    char line[128];
    gets(line);
    puts(line);
}

void greet(const char *name) {
    char msg[32];
    sprintf(msg, "Hello, %s!", name);
    puts(msg);
}

void list_dir(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls %s", dir);
    system(cmd);
}
