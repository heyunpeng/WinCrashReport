#pragma once
/********************************************************************
	created:	2011/09/06
	created:	6:9:2011   15:20
	filename: 	d:\WorkStation\StreamServer\WinCrashReport\ExceptionHandler.h
	file path:	d:\WorkStation\StreamServer\WinCrashReport
	file base:	ExceptionHandler
	file ext:	h
	author:		harrison
	
	purpose:	
*********************************************************************/

#ifdef _H_EXCEPTION_MODULE_SDK
#define _H_EXCEPTION_MODULE_CLASS_MODE __declspec(dllexport)
#else
#define _H_EXCEPTION_MODULE_CLASS_MODE __declspec(dllimport)
#endif

#ifndef _H_EXCEPTION_MODULE_SDK
#pragma comment(lib,"WinCrashReport.lib")		
#endif

typedef struct _EXCEPTION_POINTERS EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
void _H_EXCEPTION_MODULE_CLASS_MODE ExceptionHandler(unsigned int, PEXCEPTION_POINTERS lpCeption);


/*
example:
_set_se_translator(ExceptionHandler);
try
{
}
catch(...)
{
}
*/