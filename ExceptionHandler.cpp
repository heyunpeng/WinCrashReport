#include "stdafx.h"
#include "ExceptionHandler.h"
#include "GetWinVer.h"
#include <stdarg.h>
#include <stdio.h>
#include <ImageHlp.h>

#define	ONEK			1024
#define	SIXTYFOURK		(64*ONEK)
#define	ONEM			(ONEK*ONEK)
#define	ONEG			(ONEK*ONEK*ONEK)
#pragma comment(lib, "dbghelp.lib")
//////////////////////////////////////////////////////////////////////////
//Get file name
static TCHAR * lstrrchr(TCHAR* string, int ch)
{
	TCHAR *start = (TCHAR *)string;

	while (*string++)                       /* find end of string */
		;
	/* search towards front */
	while (--string != start && *string != (TCHAR) ch)
		;

	if (*string == (TCHAR) ch)                /* char found ? */
		return (TCHAR *)string;

	return NULL;
}
static TCHAR * GetFilePart(TCHAR* source)
{
	TCHAR *result = lstrrchr(source, _T('\\'));
	if (result)
		result++;
	else
		result = (TCHAR *)source;
	return result;
}
void WriteLogFile(HANDLE hLogFile, TCHAR* Format, ...)
{
	static TCHAR szLogBuffer[1024] = {0};

	int nIndex = 0;
	va_list argList;
	va_start(argList, Format);
	nIndex += wvsprintf(&szLogBuffer[nIndex], Format, argList);
	va_end(argList);

	DWORD nNumBytes = 0;
	::WriteFile(hLogFile, szLogBuffer, (DWORD)strlen(szLogBuffer), &nNumBytes, NULL);
}
//////////////////////////////////////////////////////////////////////////
const TCHAR *GetExceptionDescription(DWORD ExceptionCode)
{
	struct ExceptionNames
	{
		DWORD	ExceptionCode;
		TCHAR *	ExceptionName;
	};

	ExceptionNames ExceptionMap[] =
	{
		{0x40010005, _T("a Control-C")},
		{0x40010008, _T("a Control-Break")},
		{0x80000002, _T("a Datatype Misalignment")},
		{0x80000003, _T("a Breakpoint")},
		{0xc0000005, _T("an Access Violation")},
		{0xc0000006, _T("an In Page Error")},
		{0xc0000017, _T("a No Memory")},
		{0xc000001d, _T("an Illegal Instruction")},
		{0xc0000025, _T("a Noncontinuable Exception")},
		{0xc0000026, _T("an Invalid Disposition")},
		{0xc000008c, _T("a Array Bounds Exceeded")},
		{0xc000008d, _T("a Float Denormal Operand")},
		{0xc000008e, _T("a Float Divide by Zero")},
		{0xc000008f, _T("a Float Inexact Result")},
		{0xc0000090, _T("a Float Invalid Operation")},
		{0xc0000091, _T("a Float Overflow")},
		{0xc0000092, _T("a Float Stack Check")},
		{0xc0000093, _T("a Float Underflow")},
		{0xc0000094, _T("an Integer Divide by Zero")},
		{0xc0000095, _T("an Integer Overflow")},
		{0xc0000096, _T("a Privileged Instruction")},
		{0xc00000fD, _T("a Stack Overflow")},
		{0xc0000142, _T("a DLL Initialization Failed")},
		{0xe06d7363, _T("a Microsoft C++ Exception")},
	};

	for (int i = 0; i < sizeof(ExceptionMap) / sizeof(ExceptionMap[0]); i++)
		if (ExceptionCode == ExceptionMap[i].ExceptionCode)
			return ExceptionMap[i].ExceptionName;

	return _T("An unknown exception type");
}
void DumpSystemInformation(HANDLE hLogFile, TCHAR* lpModuleName)
{
	//system user name
	DWORD nUserNameSize = 120;
	TCHAR szTemp[120] = {0};
	if (!GetUserName(szTemp, &nUserNameSize))
		strcpy_s(szTemp, 120, "UnKnow");

	WriteLogFile(hLogFile, "%s run by %s.\r\n", lpModuleName, szTemp);

	//system version
	TCHAR szWinVer[50] = {0};
	TCHAR szMajorMinorBuild[50] = {0};
	int nWinVer;
	GetWinVer(szWinVer, &nWinVer, szMajorMinorBuild);
	WriteLogFile(hLogFile, "Operating system version:%s(%s).\r\n", szWinVer, szMajorMinorBuild);

	//process state
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	WriteLogFile(hLogFile, "%d process, type %d.\r\n", sysinfo.dwNumberOfProcessors, sysinfo.dwProcessorType);

	//memory state
	MEMORYSTATUS meminfo;
	GlobalMemoryStatus(&meminfo);
	WriteLogFile(hLogFile, _T("%d%% memory in use.\r\n"), meminfo.dwMemoryLoad);
	WriteLogFile(hLogFile, _T("%d MBytes physical memory.\r\n"), (meminfo.dwTotalPhys+ONEM-1)/ONEM);
	WriteLogFile(hLogFile, _T("%d MBytes physical memory free.\r\n"), (meminfo.dwAvailPhys+ONEM-1)/ONEM);
	WriteLogFile(hLogFile, _T("%d MBytes paging file.\r\n"), (meminfo.dwTotalPageFile+ONEM-1)/ONEM);
	WriteLogFile(hLogFile, _T("%d MBytes paging file free.\r\n"), (meminfo.dwAvailPageFile+ONEM-1)/ONEM);
	WriteLogFile(hLogFile, _T("%d MBytes user address space.\r\n"), (meminfo.dwTotalVirtual+ONEM-1)/ONEM);
	WriteLogFile(hLogFile, _T("%d MBytes user address space free.\r\n"), (meminfo.dwAvailVirtual+ONEM-1)/ONEM);
}
static bool DumpModuleInfo(HANDLE LogFile, HINSTANCE ModuleHandle, int nIndex)
{
	TCHAR szModName[MAX_PATH] = {0};
	__try
	{
		if (GetModuleFileName(ModuleHandle, szModName, MAX_PATH) > 0)
		{
			// If GetModuleFileName returns greater than zero then this must
			// be a valid code module address. Therefore we can try to walk
			// our way through its structures to find the link time stamp.
			IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER*)ModuleHandle;
			if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic)
				return false;

			IMAGE_NT_HEADERS *NTHeader = (IMAGE_NT_HEADERS*)((TCHAR *)DosHeader
				+ DosHeader->e_lfanew);
			if (IMAGE_NT_SIGNATURE != NTHeader->Signature)
				return false;

			WriteLogFile(LogFile, _T("Module Index %d, Name:%s\r\n"), nIndex, szModName);
			WriteLogFile(LogFile, _T("Image Base: 0x%08x  Image Size: 0x%08x\r\n"), NTHeader->OptionalHeader.ImageBase, NTHeader->OptionalHeader.SizeOfImage);
			WriteLogFile(LogFile, _T("Checksum:   0x%08x  Time Stamp: 0x%08x\r\n"), NTHeader->OptionalHeader.CheckSum, NTHeader->FileHeader.TimeDateStamp);
			return true;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return true;
}
void DumpStackStak(HANDLE hLogFile, PEXCEPTION_POINTERS lpExcetion)
{
	STACKFRAME stackFrame;
#ifdef _X86_
	stackFrame.AddrPC.Offset = lpExcetion->ContextRecord->Eip;
	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrStack.Offset = lpExcetion->ContextRecord->Esp;
	stackFrame.AddrStack.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Offset = lpExcetion->ContextRecord->Ebp;
	stackFrame.AddrFrame.Mode = AddrModeFlat;
#else
	stackFrame.AddrPC.Offset       = (DWORD)lpExcetion->ContextRecord->Fir ;
	stackFrame.AddrPC.Mode         = AddrModeFlat ;
	stackFrame.AddrReturn.Offset   = (DWORD)lpExcetion->ContextRecord->IntRa;
	stackFrame.AddrReturn.Mode     = AddrModeFlat ;
	stackFrame.AddrStack.Offset    = (DWORD)lpExcetion->ContextRecord->IntSp;
	stackFrame.AddrStack.Mode      = AddrModeFlat ;
	stackFrame.AddrFrame.Offset    = (DWORD)lpExcetion->ContextRecord->IntFp;
	stackFrame.AddrFrame.Mode      = AddrModeFlat ;
#endif

	//set up symbol engine
	DWORD dwOpts = SymGetOptions();
	SymSetOptions(dwOpts|SYMOPT_DEFERRED_LOADS|SYMOPT_LOAD_LINES);
	SymInitialize(GetCurrentProcess(), NULL, TRUE);

#ifdef _WIN64
#define CH_MACHINE IMAGE_FILE_MACHINE_IA64
#else
#define CH_MACHINE IMAGE_FILE_MACHINE_I386
#endif

	WriteLogFile(hLogFile, "\r\n\r\nStack trace list:\r\n");
	do 
	{
		BOOL bRet = StackWalk(CH_MACHINE, GetCurrentProcess(), GetCurrentThread(), &stackFrame, lpExcetion->ContextRecord,
			(PREAD_PROCESS_MEMORY_ROUTINE)ReadProcessMemory, SymFunctionTableAccess, SymGetModuleBase, NULL);
		if (bRet == FALSE || stackFrame.AddrFrame.Offset == 0)
			break;

		DWORD dwModuleBase = SymGetModuleBase(GetCurrentProcess(), stackFrame.AddrPC.Offset);
		if (dwModuleBase == 0)
			break;

		//module name of call
		TCHAR szModuleName[MAX_PATH] = {0};
		GetModuleFileName((HMODULE)dwModuleBase, szModuleName, MAX_PATH);

		//funtion name
		DWORD dwDisp = 0;
		TCHAR szFuntionName[MAX_PATH+sizeof(IMAGEHLP_SYMBOL)] = {0};
		PIMAGEHLP_SYMBOL lpSymb = (PIMAGEHLP_SYMBOL)szFuntionName;
		lpSymb->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
		lpSymb->MaxNameLength = MAX_PATH;
		SymGetSymFromAddr(GetCurrentProcess(), stackFrame.AddrPC.Offset, &dwDisp, lpSymb);

		//line number and filename
		IMAGEHLP_LINE hlpLine;
		SymGetLineFromAddr(GetCurrentProcess(), (DWORD)stackFrame.AddrPC.Offset, &dwDisp, &hlpLine);
		WriteLogFile(hLogFile, "%s-%s %s::%d\r\n", lpSymb->Name, GetFilePart(szModuleName), hlpLine.FileName, hlpLine.LineNumber);
	} while (1);
}
void DumpModuleList(HANDLE LogFile)
{
	SYSTEM_INFO	SystemInfo;
	GetSystemInfo(&SystemInfo);

	// Set NumPages to the number of pages in the 4GByte address space
	const size_t PageSize = SystemInfo.dwPageSize;
	const size_t NumPages = 4 * size_t(ONEG / PageSize);
	size_t pageNum = 0;
	void *LastAllocationBase = 0;
	int nModuleIndex = 1;

	WriteLogFile(LogFile, "\r\n\r\nModule list of process\r\n");
	while (pageNum < NumPages)
	{
		MEMORY_BASIC_INFORMATION MemInfo;
		if (VirtualQuery((void *)(pageNum * PageSize), &MemInfo, sizeof(MemInfo)) && MemInfo.RegionSize > 0)
		{
			//Next module start address
			pageNum += MemInfo.RegionSize / PageSize;
			if (MemInfo.State == MEM_COMMIT && MemInfo.AllocationBase > LastAllocationBase)
			{
				// Look for new blocks of committed memory, and try
				// recording their module names - this will fail
				// gracefully if they aren't code modules
				LastAllocationBase = MemInfo.AllocationBase;
				DumpModuleInfo(LogFile, (HINSTANCE)LastAllocationBase, nModuleIndex);
				nModuleIndex++;
			}
		}
		else
		{
			// If VirtualQuery fails we advance by 64K because that is the
			// granularity of address space doled out by VirtualAlloc()
			pageNum += SIXTYFOURK / PageSize;
		}
	}
}
//////////////////////////////////////////////////////////////////////////
void ExceptionHandler(unsigned int, PEXCEPTION_POINTERS lpCeption)
{
	//Get time
	SYSTEMTIME st;
	GetLocalTime(&st);
	TCHAR szTime[120] = {0};
	sprintf_s(szTime, 120, "%d-%d-%d-%d-%d-%d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	//Get current module name
	TCHAR* lpCurModuleName = _T("Current Module name");
	TCHAR szModuleName[MAX_PATH] = {0};
	if (GetModuleFileName(NULL, szModuleName, MAX_PATH) > 0)
		lpCurModuleName = GetFilePart(szModuleName);

	//Create log file
	TCHAR szFilePath[MAX_PATH] = {0};
	TCHAR szLogPath[MAX_PATH] = {0};
	GetCurrentDirectory(MAX_PATH, szFilePath);
	sprintf_s(szLogPath, MAX_PATH, "%s\\Exception-%s.log", szFilePath, szTime);

	HANDLE hLogFile = CreateFile(szLogPath, GENERIC_WRITE, 0, 0, 
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, 0);
	if (hLogFile == INVALID_HANDLE_VALUE)
		return;// EXCEPTION_CONTINUE_SEARCH;

	PEXCEPTION_RECORD Exception = lpCeption->ExceptionRecord;
	PCONTEXT          Context   = lpCeption->ContextRecord;
	TCHAR szCrashModuleName[MAX_PATH] = {0};
	TCHAR* lpCrashName = _T("Exception Process Name");
	MEMORY_BASIC_INFORMATION memInfo;
	// VirtualQuery can be used to get the allocation base associated with a
	// code address, which is the same as the ModuleHandle. This can be used
	// to get the filename of the module that the crash happened in.
	if (VirtualQuery((LPCVOID)Context->Eip, &memInfo, sizeof(memInfo)) && (GetModuleFileName((HMODULE)memInfo.AllocationBase, szCrashModuleName, MAX_PATH) > 0))
		lpCrashName = GetFilePart(szCrashModuleName);
	WriteLogFile(hLogFile, "%s caused %s(0x%08x) in module %s at %04x:%08x.\r\n",
		lpCurModuleName, GetExceptionDescription(Exception->ExceptionCode), Exception->ExceptionCode, lpCrashName, Context->SegCs, Context->Eip);

	//Write system info to logfile
	DumpSystemInformation(hLogFile, lpCurModuleName);

	// Print out the bytes of code at the instruction pointer. Since the
	// crash may have been caused by an instruction pointer that was bad,
	// this code needs to be wrapped in an exception handler, in case there
	// is no memory to read. If the dereferencing of code[] fails, the
	// exception handler will print '??'.
	WriteLogFile(hLogFile, _T("\r\n\r\nCode Start CS:EIP:\r\n"));
	BYTE * code = (BYTE *)Context->Eip;
	for (int codebyte = 0; codebyte < 16; codebyte++)
	{
		__try
		{
			WriteLogFile(hLogFile, _T("%02x "), code[codebyte]);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			WriteLogFile(hLogFile, _T("?? "));
		}
	}
	//Write Stack information to logfile
	DumpStackStak(hLogFile, lpCeption);
	//Write module of process information to logfile
	DumpModuleList(hLogFile);
	CloseHandle(hLogFile);
	
	//Create dump file
	sprintf_s(szLogPath, MAX_PATH, "%s\\Exception-%s.dmp", szFilePath, szTime);
	HANDLE hDumpFile = CreateFile(szLogPath, GENERIC_WRITE, 0, 0, 
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, 0);
	if (hDumpFile == INVALID_HANDLE_VALUE)
		return;// EXCEPTION_CONTINUE_SEARCH;
	
	MINIDUMP_EXCEPTION_INFORMATION eInfo;
	eInfo.ThreadId = GetCurrentThreadId();
	eInfo.ExceptionPointers = lpCeption;
	eInfo.ClientPointers = FALSE;
	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hDumpFile, MiniDumpNormal, &eInfo, NULL, NULL);
	CloseHandle(hDumpFile);
}