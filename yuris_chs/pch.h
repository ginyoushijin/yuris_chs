// pch.h: 这是预编译标头文件。
// 下方列出的文件仅编译一次，提高了将来生成的生成性能。
// 这还将影响 IntelliSense 性能，包括代码完成和许多代码浏览功能。
// 但是，如果此处列出的文件中的任何一个在生成之间有更新，它们全部都将被重新编译。
// 请勿在此处添加要频繁更新的文件，这将使得性能优势无效。
#ifndef PCH_H
#define PCH_H

// 添加要在此处预编译的标头
#include "framework.h"

typedef HANDLE(WINAPI* PFCREATEFILEA)(LPSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

typedef DWORD(WINAPI* PFGETFILEATTRIBUTESA)(LPCSTR lpFileName);

extern "C" { _declspec(dllexport)  int illusion(); }

extern PVOID orgCreateFileA;

extern PVOID orgGetFileAttributesA;



HANDLE WINAPI piecesCreateFile(LPSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

///<summary>
///pieces在调用ymv前会先调用GetFileAttributesA检测
///</summary>
///<param name="lpFileName">目标文件名</param>
///<returns></returns>
DWORD WINAPI piecesFileAttributes(LPSTR lpFileName);


/// <summary>
/// IATHOOK
/// </summary>
/// <param name="hModule">目标句柄</param>
/// <param name="pszFileName">目标dll</param>
/// <param name="pszProcName">hook目标函数名</param>
/// <param name="pNewProc">要替换的地址</param>
/// <param name="orgAdress">保存原地址</param>
/// <returns></returns>
BOOL IATHOOK(HMODULE hModule, PCSTR pszFileName, PCSTR pszProcName, PVOID pNewProc, PVOID* orgAdress);

PBYTE RvaAdjust(_Pre_notnull_ PIMAGE_DOS_HEADER pDosHeader, _In_ DWORD raddr);

BOOL PatchWrite(LPVOID lpAddr, LPCVOID lpBuf, DWORD nSize);

#endif //PCH_H
