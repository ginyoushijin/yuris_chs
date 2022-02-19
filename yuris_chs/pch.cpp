// pch.cpp: 与预编译标头对应的源文件

#include "pch.h"
#pragma warning(disable:6031 6387)
// 当使用预编译的头时，需要使用此源文件，编译才能成功。

PVOID orgCreateFileA = NULL;

PVOID orgGetFileAttributesA = NULL;

int illusion() {
	return 0;
}

HANDLE WINAPI piecesCreateFile(LPSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	char* fileEx = strrchr(lpFileName, '.');
	if (!(strcmp("ymv", fileEx + 1))) {	//判断是否是要获取ymv文件的句柄
		int wlen = MultiByteToWideChar(936, 0, lpFileName, -1, NULL, 0);
		WCHAR* wbuffer = new WCHAR[wlen];
		memset(wbuffer, 0, wlen * sizeof(WCHAR));
		MultiByteToWideChar(936, 0, lpFileName, -1, wbuffer, wlen);
		HANDLE piecesFileHandle = CreateFileW(wbuffer, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
		delete[]wbuffer;
		return piecesFileHandle;
	}
	else
	{
		return ((PFCREATEFILEA)orgCreateFileA)(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}
}

DWORD WINAPI piecesFileAttributes(LPSTR lpFileName) {
	char* fileEx = strrchr(lpFileName, '.');
	if (!strcmp("ymv", fileEx + 1)) {
		int wlen = MultiByteToWideChar(936, 0, lpFileName, -1, NULL, 0);
		WCHAR* wbuffer = new WCHAR[wlen];
		memset(wbuffer, 0, wlen * sizeof(WCHAR));
		MultiByteToWideChar(936, 0, lpFileName, -1, wbuffer, wlen);
		DWORD piecesFileStatus = GetFileAttributesW(wbuffer);
		delete[]wbuffer;
		return piecesFileStatus;
	}
	else
	{
		return ((PFGETFILEATTRIBUTESA)orgGetFileAttributesA)(lpFileName);
	}
}


BOOL IATHOOK(HMODULE hModule, PCSTR pszFileName, PCSTR pszProcName, PVOID pNewProc, PVOID* orgAdress) {
	PIMAGE_DOS_HEADER pDosHeader;	//定义一个dos头
	if (hModule == NULL) {	//判断传入的句柄是否为null,如果为null则会获取当前线程的dos头
		pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandleW(NULL);
	}
	else
	{
		pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	}
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {	//判断dos(pe)头
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);	//获取nt头
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) { //判断nt头
		return FALSE;
	}
	if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {	//判断nt32的大小
		return FALSE;
	}
	PIMAGE_IMPORT_DESCRIPTOR iidp = (PIMAGE_IMPORT_DESCRIPTOR)RvaAdjust(pDosHeader, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);	//获取该进程的导入表
	if (iidp == NULL) {	//判断当前进程是否有导入表
		return FALSE;
	}
	for (; iidp->OriginalFirstThunk != 0; iidp++)	//遍历导入表
	{
		PCSTR pszName = (PCHAR)RvaAdjust(pDosHeader, iidp->Name);	//获取当前_IMAGE_IMPORT_DESCRIPTOR(dll)的name

		if (pszName == NULL) {	//dll名不能为空
			return FALSE;
		}
		if (_stricmp(pszName, pszFileName) != 0) {// 判断DLL文件名(忽略大小写),不一致则直接跳过当前_IMAGE_IMPORT_DESCRIPTOR
			continue;
		}
		PIMAGE_THUNK_DATA pThunks = (PIMAGE_THUNK_DATA)RvaAdjust(pDosHeader, iidp->OriginalFirstThunk);	//获取当前dll的INT
		PVOID* pAddrs = (PVOID*)RvaAdjust(pDosHeader, iidp->FirstThunk);	//获取当前dll的IAT

		if (pThunks == NULL) {
			continue;
		}
		// 遍历从该DLL导入的函数
		for (DWORD nNames = 0; pThunks[nNames].u1.Ordinal; nNames++)
		{
			DWORD nOrdinal = 0;
			PCSTR pszFunc = NULL;

			if (IMAGE_SNAP_BY_ORDINAL(pThunks[nNames].u1.Ordinal)) {
				nOrdinal = (DWORD)IMAGE_ORDINAL(pThunks[nNames].u1.Ordinal);
			}
			else {
				pszFunc = (PCSTR)RvaAdjust(pDosHeader, (DWORD)pThunks[nNames].u1.AddressOfData + 2); //得到这个dll的函数名
			}
			if (pszFunc == NULL) {
				// 没有函数名，说明函数是按序号导入的。
				continue;
			}
			if (strcmp(pszFunc, pszProcName) == 0) {
				// 已找到函数，改写函数地址。
				if (orgAdress != NULL) {
					*orgAdress = pAddrs[nNames];
				}
				PatchWrite(&pAddrs[nNames], &pNewProc, sizeof(pNewProc));
				return TRUE;
			}
		}
	}
	return FALSE;
}

PBYTE RvaAdjust(_Pre_notnull_ PIMAGE_DOS_HEADER pDosHeader, _In_ DWORD raddr)	//通过偏移计算出一个地址,dos头不能是空指针
{
	if (raddr != NULL) {
		return ((PBYTE)pDosHeader) + raddr;
	}
	return NULL;
}

BOOL PatchWrite(LPVOID lpAddr, LPCVOID lpBuf, DWORD nSize)
{
	DWORD dwProtect;
	if (VirtualProtect(lpAddr, nSize, PAGE_EXECUTE_READWRITE, &dwProtect)) {//修改内存属性
		memcpy(lpAddr, lpBuf, nSize);	//覆盖函数地址
		VirtualProtect(lpAddr, nSize, dwProtect, &dwProtect);	//恢复内存属性
		return  TRUE;
	}
	return FALSE;
}
