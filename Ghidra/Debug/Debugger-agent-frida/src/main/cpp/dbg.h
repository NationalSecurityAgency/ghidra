#pragma once
#define WIN32_LEAN_AND_MEAN
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include "stdio.h"
#include <process.h>
#include <share.h>

#define dlog(format, ...) _dbglog(0, __DbgLogNorm,  __LINE__,__FILE__,__func__, format, ## __VA_ARGS__)

static FILE* logfile;
typedef enum { __DbgLogNorm, __DbgLogFunc, __DbgLogFatal } __DbgLogType_t;//dbglogfunc means we are logging a call we commented out or norm trace
void _fdbglog_help(FILE* f, const char* prefix_str, const char* format, va_list args) {
	fputs(prefix_str, f);
	vfprintf(f, format, args);
	fputs("\n", f);
	fflush(f);

}
void _fdbglog_msg(const char* prefix_str, const char* format, va_list args) {
	//char buffer[1024];
	//OutputDebugString(prefix_str);
	//vsprintf_s(buffer, sizeof(buffer), format, args);
	//OutputDebugString(buffer);
	//OutputDebugString("\n");
}
void dbgloginit() {
	logfile = _fsopen("ghdbg.log", "w", _SH_DENYNO);
}
int _dbglog(int retval, __DbgLogType_t LogType, int lineno, const char* file, const char* func, const char* format, ...) {

	va_list args;
	va_start(args, format);
	time_t rawtime;
	struct tm timeinfo;
	const char* file_end = strrchr(file, '\\');
	if (file_end != NULL)
		file = file_end + 1;

	time(&rawtime);
	localtime_s(&timeinfo, &rawtime);
	char prefix_str[150];
	sprintf_s(prefix_str, sizeof(prefix_str), "%2d:%02d:%02d %s:%d::%s %s", timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, file, lineno, func, LogType == __DbgLogFatal ? "FLOG " : "");

	//_fdbglog_help(stderr, prefix_str, format, args);

	_fdbglog_help(logfile, prefix_str, format, args);
	_fdbglog_msg(prefix_str, format, args);
	//DbgPrint();
	va_end(args);
	if (LogType == __DbgLogFatal)
		exit(-99);
	return retval;
}

