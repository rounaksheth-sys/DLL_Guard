 #include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        FILE *f = fopen("demo_dll_loaded.txt", "a");
        if (f) { fputs("harmless demo DLL was loaded\n", f); fclose(f); }
    }
    return TRUE;
}