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
package agent.frida.jna;

import java.util.List;

import com.sun.jna.*;
import com.sun.jna.platform.linux.LibC;

public interface FridaNative extends LibC {

	FridaNative INSTANCE = Native.load("frida-core", FridaNative.class); //??

	public static final int GUM_MAX_PATH = 261;
	public static final int GUM_MAX_SYMBOL_NAME = 2049;
	public static final int GUM_MAX_BACKTRACE_DEPTH = 16;

	public enum GumOs {
		GUM_OS_WINDOWS("windows"),
		GUM_OS_MACOS("macos"),
		GUM_OS_LINUX("linux"),
		GUM_OS_IOS("ios"),
		GUM_OS_ANDROID("android"),
		GUM_OS_FREEBSD("freebsd"),
		GUM_OS_QNX("qnx");

		final String str;

		GumOs(String str) {
			this.str = str;
		}

		@Override
		public String toString() {
			return str;
		}
	}

	public enum GumThreadState {
		GUM_THREAD_RUNNING("running"),
		GUM_THREAD_STOPPED("stopped"),
		GUM_THREAD_WAITING("waiting"),
		GUM_THREAD_UNINTERRUPTIBLE("uninterruptible"),
		GUM_THREAD_HALTED("halted");

		final String str;

		GumThreadState(String str) {
			this.str = str;
		}

		@Override
		public String toString() {
			return str;
		}
	}

	public static class GError extends Structure {
		public static class ByReference extends GError
				implements Structure.ByReference {
			// NO CODE
		}

		public static final List<String> FIELDS = createFieldsOrder("domain", "code", "message");

		public volatile int domain;
		public volatile int code;
		public volatile String message;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class GumMemoryRange extends Structure {
		public static class ByReference extends GumMemoryRange
				implements Structure.ByReference {
			// NO CODE
		}

		public static final List<String> FIELDS = createFieldsOrder("address", "size");

		public NativeLong address;
		public NativeLong size;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class GumFileMapping extends Structure {
		public static class ByReference extends GumFileMapping
				implements Structure.ByReference {
			// NO CODE
		}

		public static final List<String> FIELDS = createFieldsOrder("path", "offset", "size");

		public Pointer path;
		public NativeLong offset;
		public NativeLong size;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class GumModuleDetails extends Structure {
		public static class ByReference extends GumModuleDetails
				implements Structure.ByReference {
			// NO CODE
		}

		public static final List<String> FIELDS = createFieldsOrder("name", "range", "path");

		public Pointer name;
		public GumMemoryRange.ByReference range;
		public Pointer path;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class GumRangeDetails extends Structure {
		public static class ByReference extends GumRangeDetails
				implements Structure.ByReference {
			// NO CODE
		}

		public static final List<String> FIELDS = createFieldsOrder("range", "protection", "file");

		public GumMemoryRange.ByReference range;
		public NativeLong protection;
		public GumFileMapping.ByReference file;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class GumReturnAddressDetails extends Structure {

		public static class ByReference extends GumReturnAddressDetails
				implements Structure.ByReference {
			// NO CODE
		}

		public static final List<String> FIELDS = createFieldsOrder("address",
			"moduleName", "functionName", "fileName", "lineNumber");

		public NativeLong address;
		public byte[] moduleName = new byte[GUM_MAX_PATH];
		public byte[] functionName = new byte[GUM_MAX_SYMBOL_NAME];
		public byte[] fileName = new byte[GUM_MAX_PATH];
		public NativeLong lineNumber;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class GumReturnAddressArray extends Structure {
		public static class ByReference extends GumReturnAddressArray
				implements Structure.ByReference {
			// NO CODE
		}

		public static final List<String> FIELDS = createFieldsOrder("len", "items");

		public NativeLong len;
		public NativeLong[] items = new NativeLong[GUM_MAX_BACKTRACE_DEPTH];

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class GumMallocRangeDetails extends Structure {
		public static class ByReference extends GumMallocRangeDetails
				implements Structure.ByReference {
			// NO CODE
		}

		public static final List<String> FIELDS = createFieldsOrder("range");

		public GumMemoryRange.ByReference range;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static interface ExceptionCallback extends Callback {
		void invoke(Pointer details);
	}

	public static interface MessageCallback extends Callback {
		void invoke(Pointer script, String message, Pointer data, Pointer userData);
	}

	void GH_frida_init();

	Pointer GH_frida_device_manager_new();

	void GH_frida_device_manager_close_sync(Pointer manager, Pointer cancellable,
			GError.ByReference error);

	Pointer GH_frida_device_manager_find_device_by_id_sync(Pointer manager, String id,
			NativeLong timeout, Pointer cancellable, GError.ByReference error);

	Pointer GH_frida_device_manager_find_device_by_type_sync(Pointer manager, NativeLong type,
			NativeLong timeout, Pointer cancellable, GError.ByReference error);

	Pointer GH_frida_device_manager_enumerate_devices_sync(Pointer manager, Pointer cancellable,
			GError.ByReference error);

	Integer GH_frida_device_list_size(Pointer deviceList);

	Pointer GH_frida_device_list_get(Pointer deviceList, int i);

	String GH_frida_device_get_id(Pointer device);

	String GH_frida_device_get_name(Pointer device);

	Pointer GH_frida_device_enumerate_processes_sync(Pointer device, NativeLong options,
			Pointer cancellable, GError.ByReference error);

	Integer GH_frida_process_list_size(Pointer processList);

	Pointer GH_frida_process_list_get(Pointer processList, int i);

	NativeLong GH_frida_process_get_pid(Pointer process);

	String GH_frida_process_get_name(Pointer process);

	Pointer GH_frida_process_get_parameters(Pointer process);

	Pointer GH_frida_device_enumerate_applications_sync(Pointer device, NativeLong options,
			Pointer cancellable, GError.ByReference error);

	Integer GH_frida_application_list_size(Pointer processList);

	Pointer GH_frida_application_list_get(Pointer processList, int i);

	NativeLong GH_frida_application_get_pid(Pointer process);

	String GH_frida_application_get_name(Pointer process);

	String GH_frida_application_get_identifier(Pointer process);

	Pointer GH_frida_application_get_parameters(Pointer process);

	Pointer GH_frida_device_attach_sync(Pointer localDevice, NativeLong pid, NativeLong options,
			Pointer cancellable, GError.ByReference error);

	NativeLong GH_frida_device_spawn_sync(Pointer localDevice, String fileName, NativeLong options,
			Pointer cancellable, GError.ByReference error);

	NativeLong GH_frida_session_get_pid(Pointer session);

	Pointer GH_frida_device_get_process_by_pid_sync(Pointer localDevice, NativeLong pid,
			Pointer options, Pointer cancellable, GError.ByReference error);

	Pointer GH_frida_device_resume_sync(Pointer localDevice, NativeLong pid, Pointer cancellable,
			GError.ByReference error);

	Pointer GH_frida_device_kill_sync(Pointer localDevice, NativeLong pid, Pointer cancellable,
			GError.ByReference error);

	boolean GH_frida_session_is_detached(Pointer session);

	void GH_frida_session_detach_sync(Pointer session, Pointer cancellable,
			GError.ByReference error);

	void GH_frida_session_resume_sync(Pointer session, Pointer cancellable,
			GError.ByReference error);

	Pointer GH_frida_script_options_new();

	void GH_frida_script_options_set_name(Pointer options, String name);

	void GH_frida_script_options_set_runtime(Pointer options, NativeLong runtime);

	Pointer GH_frida_session_create_script_sync(Pointer session, String commands, Pointer options,
			Pointer cancellable, GError.ByReference error);

	void GH_frida_unref(Pointer script);

	void GH_frida_script_load_sync(Pointer script, Pointer cancellable, GError.ByReference error);

	void GH_frida_script_unload_sync(Pointer script, Pointer cancellable, GError.ByReference error);

	void GH_frida_session_enable_debugger_sync(Pointer session, NativeLong port,
			Pointer cancellable, GError.ByReference error);

	NativeLong GH_frida_bus_session_get_type();

	// These are equivalent but version-dependent
	NativeLong GH__frida_g_signal_connect_data(Pointer script, String signal,
			MessageCallback closure, Pointer data, Pointer notify, NativeLong after);

	NativeLong GH_g_signal_connect_data(Pointer script, String signal, MessageCallback closure,
			Pointer data, Pointer notify, NativeLong after);

	// These are equivalent but version-dependent
	void GH__frida_g_signal_handler_disconnect(Pointer script, NativeLong signalHandle);

	void GH_g_signal_handler_disconnect(Pointer script, NativeLong signalHandle);

	void GH_g_signal_emit_by_name(Pointer instance, String detailed_signal);

	NativeLong GH_g_signal_new(String signal_name, NativeLong itype, NativeLong signal_flags,
			NativeLong class_offset, Pointer accumulator, Pointer accu_data,
			Pointer c_marshaller, NativeLong return_type, NativeLong n_params, NativeLong ptype);

}
