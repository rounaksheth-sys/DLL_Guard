#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    strcat(path, "harmless.dll");

    HMODULE h = LoadLibraryA(path);
    printf(h ? "Loaded: %s\n" : "Failed to load: %s\n", path);
    printf("Press Enter to exit...\n");
    getchar();
    return 0;
}