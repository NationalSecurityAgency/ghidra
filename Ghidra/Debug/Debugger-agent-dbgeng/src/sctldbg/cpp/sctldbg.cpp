/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdlib.h>
#include <string.h>

#define INITGUID
#include <dbgeng.h>
#include <Windows.h>

#include <jni.h>

JavaVM* jvm = NULL;
JNIEnv* env = NULL;

char JDK_JVM_DLL_PATH[] = "\\jre\\bin\\server\\jvm.dll";
char JRE_JVM_DLL_PATH[] = "\\bin\\server\\jvm.dll";

char MAIN_CLASS[] = "sctldbgeng/sctl/DbgEngSctlServer";

char CP_PREFIX[] = "-Djava.class.path=";

typedef jint (_cdecl *CreateJavaVMFunc)(JavaVM**, void**, void*);


#define CHECK_RC(v, f, x) do { \
	HRESULT ___hr = (x); \
	if (___hr < 0) { \
		fprintf(stderr, "FAILED on line %d: HRESULT=%08x\n", __LINE__, ___hr); \
		goto f; \
	} else if (___hr == S_OK) { \
		v = 1; \
	} else { \
		v = 0; \
	} \
} while (0)


#if 0
class MyEventCallbacks : public DebugBaseEventCallbacks {
public:
	STDMETHOD_(ULONG, AddRef)(THIS) {
		InterlockedIncrement(&m_ulRefCount);
		return m_ulRefCount;
	}

	STDMETHOD_(ULONG, Release)(THIS) {
		ULONG ulRefCount = InterlockedDecrement(&m_ulRefCount);
		if (m_ulRefCount == 0) {
			delete this;
		}
		return ulRefCount;
	}

	STDMETHOD(GetInterestMask)(_Out_ PULONG Mask) {
		*Mask = DEBUG_EVENT_CREATE_PROCESS | DEBUG_EVENT_CREATE_THREAD;
		return S_OK;
	}

	STDMETHOD(CreateProcess)(
		THIS_
		_In_ ULONG64 ImageFileHandle,
		_In_ ULONG64 Handle,
		_In_ ULONG64 BaseOffset,
		_In_ ULONG ModuleSize,
		_In_ PCSTR ModuleName,
		_In_ PCSTR ImageName,
		_In_ ULONG CheckSum,
		_In_ ULONG TimeDateStamp,
		_In_ ULONG64 InitialThreadHandle,
		_In_ ULONG64 ThreadDataOffset,
		_In_ ULONG64 StartOffset
	) {
		UNREFERENCED_PARAMETER(ImageFileHandle);
		UNREFERENCED_PARAMETER(Handle);
		UNREFERENCED_PARAMETER(BaseOffset);
		UNREFERENCED_PARAMETER(ModuleSize);
		UNREFERENCED_PARAMETER(ModuleName);
		UNREFERENCED_PARAMETER(ImageName);
		UNREFERENCED_PARAMETER(CheckSum);
		UNREFERENCED_PARAMETER(TimeDateStamp);
		UNREFERENCED_PARAMETER(InitialThreadHandle);
		UNREFERENCED_PARAMETER(ThreadDataOffset);
		UNREFERENCED_PARAMETER(StartOffset);
		return DEBUG_STATUS_BREAK;
	}

	STDMETHOD(CreateThread)(
		THIS_
		_In_ ULONG64 Handle,
		_In_ ULONG64 DataOffset,
		_In_ ULONG64 StartOffset
	) {
		UNREFERENCED_PARAMETER(Handle);
		UNREFERENCED_PARAMETER(DataOffset);
		UNREFERENCED_PARAMETER(StartOffset);
		return DEBUG_STATUS_BREAK;
	}
private:
	ULONG m_ulRefCount = 0;
};

int main_exp00(int argc, char** argv) {
	PDEBUG_CLIENT5 pClient5 = NULL;
	PDEBUG_CONTROL4 pControl4 = NULL;
	PDEBUG_SYMBOLS3 pSymbols3 = NULL;
	int ok = 0;

	CHECK_RC(ok, EXIT, DebugCreate(IID_IDebugClient5, (PVOID*) &pClient5));
	CHECK_RC(ok, EXIT, pClient5->QueryInterface(IID_IDebugControl4, (PVOID*) &pControl4));
	CHECK_RC(ok, EXIT, pClient5->QueryInterface(IID_IDebugSymbols3, (PVOID*) &pSymbols3));

	pClient5->SetEventCallbacks(new MyEventCallbacks());

	CHECK_RC(ok, EXIT, pControl4->Execute(DEBUG_OUTCTL_ALL_CLIENTS, ".create notepad", DEBUG_EXECUTE_ECHO));
	CHECK_RC(ok, EXIT, pControl4->WaitForEvent(0, INFINITE));
	CHECK_RC(ok, EXIT, pControl4->Execute(DEBUG_OUTCTL_ALL_CLIENTS, "g", DEBUG_EXECUTE_ECHO));
	CHECK_RC(ok, EXIT, pControl4->WaitForEvent(0, INFINITE));

	ULONG64 ul64MatchHandle = 0;
	CHECK_RC(ok, EXIT, pSymbols3->StartSymbolMatch("*", &ul64MatchHandle));
	while (true) {
		char aBuffer[1024] = { 0 };
		ULONG64 ul64Offset = 0;
		CHECK_RC(ok, FINISH, pSymbols3->GetNextSymbolMatch(ul64MatchHandle, aBuffer, sizeof(aBuffer), NULL, &ul64Offset));
		printf("%016x: %s\n", ul64Offset, aBuffer);
	}
FINISH:

	fprintf(stderr, "SUCCESS\n");
EXIT:
	pClient5->SetEventCallbacks(NULL);
	pControl4->Release();
	pClient5->Release();
	return 0;
}

int main_exp01(int argc, char** argv) {
	PDEBUG_CLIENT5 pClient5 = NULL;
	int ok = 0;

	CHECK_RC(ok, EXIT, DebugCreate(IID_IDebugClient5, (PVOID*) &pClient5));

	CHECK_RC(ok, EXIT, pClient5->StartProcessServerWide(DEBUG_CLASS_USER_WINDOWS, L"tcp:port=11200", NULL));
	CHECK_RC(ok, EXIT, pClient5->WaitForProcessServerEnd(INFINITE));
EXIT:
	if (pClient5 != NULL) {
		pClient5->Release();
	}
	return 0;
}
#endif

int main_sctldbg(int argc, char** argv) {
	if (argc < 1) {
		fprintf(stderr, "Something is terribly wrong: argc == 0\n");
	}
	char* env_java_home = getenv("JAVA_HOME");
	if (env_java_home == NULL) {
		fprintf(stderr, "JAVA_HOME is not set\n");
		fflush(stderr);
		return -1;
	}
	char* java_home = strdup(env_java_home);
	size_t home_len = strlen(java_home);
	if (java_home[home_len - 1] == '\\') {
		java_home[home_len - 1] = '\0';
	}
	size_t full_len = home_len + sizeof(JDK_JVM_DLL_PATH);
	char* full_path = new char[full_len];
	HMODULE jvmDll = NULL;
	// Try the JRE path first;
	strcpy_s(full_path, full_len, java_home);
	strcat_s(full_path, full_len, JRE_JVM_DLL_PATH);
	fprintf(stderr, "Trying to find jvm.dll at %s\n", full_path);
	fflush(stderr);
	jvmDll = LoadLibraryA(full_path);
	if (jvmDll == NULL) {
		// OK, then try the JDK path
		strcpy_s(full_path, full_len, java_home);
		strcat_s(full_path, full_len, JDK_JVM_DLL_PATH);
		fprintf(stderr, "Trying to find jvm.dll at %s\n", full_path);
		fflush(stderr);
		jvmDll = LoadLibraryA(full_path);
	}

	free(full_path);
	free(java_home);

	if (jvmDll == NULL) {
		fprintf(stderr, "Could not find the jvm.dll\n");
		fflush(stderr);
		return -1;
	}
	fprintf(stderr, "Found it!\n");
	fflush(stderr);

#define USE_EXE_AS_JAR
#ifdef USE_EXE_AS_JAR
	DWORD fullpath_len = GetFullPathNameA(argv[0], 0, NULL, NULL);
	char* fullpath = new char[fullpath_len];
	GetFullPathNameA(argv[0], fullpath_len, fullpath, NULL);
	size_t cp_opt_len = sizeof(CP_PREFIX) + strlen(fullpath);
	char* cp_opt = new char[cp_opt_len];
	strcpy_s(cp_opt, cp_opt_len, CP_PREFIX);
	strcat_s(cp_opt, cp_opt_len, fullpath);
	fflush(stderr);
#endif

	JavaVMOption options[2];
	JavaVMInitArgs vm_args = { 0 };
	vm_args.version = JNI_VERSION_1_8;
	vm_args.nOptions = sizeof(options)/sizeof(options[0]);
	vm_args.options = options;
	options[0].optionString = "-Xrs";
#ifdef USE_EXE_AS_JAR
	fprintf(stderr, "Classpath: %s\n", cp_opt);
	options[1].optionString = cp_opt;
#else
	options[1].optionString = "-Djava.class.path=sctldbgeng.jar";
#endif
	//options[2].optionString = "-verbose:class";
	vm_args.ignoreUnrecognized = false;
	CreateJavaVMFunc create_jvm = NULL;
	//create_jvm = JNI_CreateJavaVM;
	create_jvm = (CreateJavaVMFunc) GetProcAddress(jvmDll, "JNI_CreateJavaVM");
	jint jni_result = create_jvm(&jvm, (void**)&env, &vm_args);

#ifdef USE_EXE_AS_JAR
	free(cp_opt);
#endif

	if (jni_result != JNI_OK) {
		jvm = NULL;
		fprintf(stderr, "Could not initialize JVM: %d: ", jni_result);
		switch (jni_result) {
		case JNI_ERR:
			fprintf(stderr, "unknown error");
			break;
		case JNI_EDETACHED:
			fprintf(stderr, "thread detached from the VM");
			break;
		case JNI_EVERSION:
			fprintf(stderr, "JNI version error");
			break;
		case JNI_ENOMEM:
			fprintf(stderr, "not enough memory");
			break;
		case JNI_EEXIST:
			fprintf(stderr, "VM already created");
			break;
		case JNI_EINVAL:
			fprintf(stderr, "invalid arguments");
			break;
		}
		fprintf(stderr, "\n");
		fflush(stderr);
		return -1;
	}

	jclass mainCls = env->FindClass(MAIN_CLASS);
	if (mainCls == NULL) {
		fprintf(stderr, "Could not find main class: %s\n", MAIN_CLASS);
		jvm->DestroyJavaVM();
		return -1;
	}

	jmethodID mainMeth = env->GetStaticMethodID(mainCls, "main", "([Ljava/lang/String;)V");
	if (mainMeth == NULL) {
		fprintf(stderr, "No main(String[] args) method in main class\n");
		jvm->DestroyJavaVM();
		return -1;
	}

	jclass stringCls = env->FindClass("java/lang/String");

	jobjectArray jargs = env->NewObjectArray(argc - 1, stringCls, NULL);
	for (int i = 1; i < argc; i++) {
		jstring a = env->NewStringUTF(argv[i]);
		if (a == NULL) {
			fprintf(stderr, "Could not create Java string for arguments.\n");
			jvm->DestroyJavaVM();
			return -1;
		}
		env->SetObjectArrayElement(jargs, i - 1, a);
	}

	env->CallStaticVoidMethod(mainCls, mainMeth, (jvalue*) jargs);

	if (env->ExceptionCheck()) {
		env->ExceptionDescribe();
		env->ExceptionClear();
	}

	jvm->DestroyJavaVM();

	return 0;
}

int main(int argc, char** argv) {
	main_sctldbg(argc, argv);
}

