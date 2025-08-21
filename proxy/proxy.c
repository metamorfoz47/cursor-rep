#ifdef _WIN32
#  include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)hModule; (void)ul_reason_for_call; (void)lpReserved;
    return TRUE;
}
#else
int main(void) { return 0; }
#endif
