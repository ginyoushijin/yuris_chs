// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		IATHOOK(NULL, "Kernel32.dll", "CreateFileA", piecesCreateFile,&orgCreateFileA);
		IATHOOK(NULL, "Kernel32.dll", "GetFileAttributesA", piecesFileAttributes,&orgGetFileAttributesA);
		break;
	case DLL_PROCESS_DETACH:
		IATHOOK(NULL, "Kernel32.dll", "CreateFileA", orgCreateFileA,NULL);
		IATHOOK(NULL, "Kernel32.dll", "GetFileAttributesA", orgGetFileAttributesA,NULL);
		break;
	}
	return TRUE;
}

