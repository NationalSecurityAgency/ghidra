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
#define INITGUID

#include <engextcpp.hpp>
#include <jni.h>

#include "resource.h"

#define CHECK_RESULT(x, y) do { \
	HRESULT hr = (x); \
	if (hr != S_OK) { \
		fprintf(stderr, "HRESULT of %s = %x\n", ##x, hr); \
		return y; \
	} \
} while (0)

class EXT_CLASS : public ExtExtension {
public:
	virtual HRESULT Initialize();
	virtual void Uninitialize();

	//virtual void OnSessionAccessible(ULONG64 Argument);

	EXT_COMMAND_METHOD(java_add_cp);
	EXT_COMMAND_METHOD(java_set);
	EXT_COMMAND_METHOD(java_get);
	EXT_COMMAND_METHOD(java_run);

	void run_command(PCSTR name);
};

EXT_DECLARE_GLOBALS();

JavaVM* jvm = NULL;
JNIEnv* env = NULL;
jclass clsCommands = NULL;

char JDK_JVM_DLL_PATH[] = "\\jre\\bin\\server\\jvm.dll";
char JRE_JVM_DLL_PATH[] = "\\bin\\server\\jvm.dll";

typedef jint (_cdecl *CreateJavaVMFunc)(JavaVM**, void**, void*);

HRESULT EXT_CLASS::Initialize() {
	HRESULT result = ExtExtension::Initialize();
	if (result != S_OK) {
		return result;
	}

	char* env_java_home = getenv("JAVA_HOME");
	if (env_java_home == NULL) {
		fprintf(stderr, "JAVA_HOME is not set\n");
		fflush(stderr);
		return E_FAIL;
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
		return E_FAIL;
	}
	fprintf(stderr, "Found it!\n");
	fflush(stderr);

	JavaVMOption options[2];
	JavaVMInitArgs vm_args = { 0 };
	vm_args.version = JNI_VERSION_1_8;
	vm_args.nOptions = sizeof(options)/sizeof(options[0]);
	vm_args.options = options;
	options[0].optionString = "-Xrs";
	options[1].optionString = "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005";
	vm_args.ignoreUnrecognized = false;
	CreateJavaVMFunc create_jvm = NULL;
	//create_jvm = JNI_CreateJavaVM;
	create_jvm = (CreateJavaVMFunc) GetProcAddress(jvmDll, "JNI_CreateJavaVM");
	jint jni_result = create_jvm(&jvm, (void**)&env, &vm_args);

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
		return E_FAIL;
	}

	HMODULE hJavaProviderModule = GetModuleHandle(TEXT("javaprovider"));
	HRSRC resCommandsClassfile = FindResource(hJavaProviderModule, MAKEINTRESOURCE(IDR_CLASSFILE1), TEXT("Classfile"));
	HGLOBAL gblCommandsClassfile = LoadResource(hJavaProviderModule, resCommandsClassfile);
	LPVOID lpCommandsClassfile = LockResource(gblCommandsClassfile);
	DWORD szCommandsClassfile = SizeofResource(hJavaProviderModule, resCommandsClassfile);

	clsCommands = env->DefineClass(
		"javaprovider/Commands", NULL, (jbyte*) lpCommandsClassfile, szCommandsClassfile
	);
	if (clsCommands == NULL) {
		fprintf(stderr, "Could not define Commands class\n");
		if (env->ExceptionCheck()) {
			env->ExceptionDescribe();
			env->ExceptionClear();
			return E_FAIL;
		}
	}

	return S_OK;
}

void EXT_CLASS::Uninitialize() {
	if (jvm != NULL) {
		jvm->DestroyJavaVM();
	}
	ExtExtension::Uninitialize();
}

void EXT_CLASS::run_command(PCSTR name) {
	// TODO: Throw an exception during load, then!
	if (jvm == NULL) {
		Out("javaprovider extension did not load properly.\n");
		return;
	}
	if (clsCommands == NULL) {
		Out("javaprovider extension did not load properly.\n");
		return;
	}

	PCSTR args = GetRawArgStr();

	jmethodID mthCommand = env->GetStaticMethodID(clsCommands, name, "(Ljava/lang/String;)V");
	if (mthCommand == NULL) {
		Out("INTERNAL ERROR: No such command: %s\n", name);
		return;
	}

	jstring argsStr = env->NewStringUTF(args);
	if (argsStr == NULL) {
		Out("Could not create Java string for arguments.\n");
		return;
	}

	env->CallStaticVoidMethod(clsCommands, mthCommand, argsStr);
	env->DeleteLocalRef(argsStr);
	if (env->ExceptionCheck()) {
		Out("Exception during javaprovider command:\n");
		env->ExceptionDescribe(); // TODO: Send this to output callbacks, not console.
		env->ExceptionClear();
	}
}

EXT_COMMAND(java_add_cp, "Add an element to the class path", "{{custom}}") {
	run_command("java_add_cp");
}

EXT_COMMAND(java_set, "Set a Java system property",	"{{custom}}") {
	run_command("java_set");
}

EXT_COMMAND(java_get, "Get a Java system property",	"{{custom}}") {
	run_command("java_get");
}

EXT_COMMAND(java_run, "Execute the named java class", "{{custom}}") {
	run_command("java_run");
}

#define JNA extern "C" __declspec(dllexport)

JNA HRESULT createClient(PDEBUG_CLIENT* client) {
	return g_ExtInstance.m_Client->CreateClient(client);
}
