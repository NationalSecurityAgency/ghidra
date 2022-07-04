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
package agent.frida.frida;

import java.util.ArrayList;
import java.util.List;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;

import agent.frida.jna.FridaNative;
import agent.frida.manager.*;
import ghidra.comm.util.BitmaskSet;
import ghidra.util.Msg;

/**
 * A wrapper for Microsoft's {@code dbgeng.dll} that presents a Java-friendly interface.
 * 
 * This is the "root interface" from which all other interfaces to {@code dbgeng.dll} are generated.
 * Not every method listed in the documentation, nor every method present in the header, is
 * implemented. Only those that were necessary to implement the SCTL adapter. However, the class and
 * interface hierarchy was designed so that adding the remaining methods should be fairly
 * straightforward. This wrapper attempts to obtain the most capable COM interfaces for the debug
 * client that it knows. Again, newer interfaces should be fairly straightforward to add.
 * 
 * Methods that are "obviously" wrappers for a COM method are left undocumented, unless there is
 * some nuance to how it has been wrapped. In many cases, a parameter which is an integer in the COM
 * method may be presented as an {@code enum} or {@link BitmaskSet} by the wrapper. Consult the MSDN
 * for the meaning of the various values and bit flags.
 * 
 * Each wrapper interface is implemented by several COM interface wrappers: one for each known COM
 * interface version. The wrapper is optimistic, in that it declares wrapper methods even for COM
 * methods that are only available in later versions. The implementations limited to earlier COM
 * interfaces should either emulate the operation, or throw an
 * {@link UnsupportedOperationException}. Where a newer method is provided by a newer interface, a
 * wrapper implementation should prefer the latest. For example, one series of interfaces introduces
 * {@code *Wide} variants of existing methods. Since Java also uses a UTF-16-like string encoding
 * internally, JNA permits wide strings to be passed by reference. Thus, the wide variant is always
 * preferred.
 * 
 * Pay careful attention to the threading requirements imposed by {@code dbgeng.dll} these can be
 * found in the MSDN. As a general rule of thumb, if the method is reentrant (i.e., it can be called
 * from any thread), it is declared in the {@code *Reentrant} variant of the wrapper interface.
 * There are few of these. Unless the documentation explicitly lists the method as reentrant, do not
 * declare it there. Many methods appear to execute successfully from the wrong thread, but cause
 * latent issues. A practice to prevent accidental use of non-reentrant methods outside of the
 * client's owning thread is to ensure that only the owning thread can see the full interface. All
 * other threads should only have access to the reentrant interface.
 * 
 * If you implement methods that introduce a new callback class, use the existing callback type
 * hierarchies as a model. There are many classes to implement. Furthermore, be sure to keep a
 * reference to any active callback instances within the wrapper that uses them. The JNA has no way
 * of knowing whether or not the instance is still being used by the external C/C++ library. If you
 * do not store a reference, the JVM will think it's garbage and free it, even though COM is still
 * using it. Drop the reference only when you are certain nothing external has a reference to it.
 */
public class FridaEng {

	private static final NativeLong FRIDA_REALM_NATIVE = new NativeLong(0);
	
	/**
	 * Create a debug client.
	 * 
	 * @return a pointer to the device manager
	 */
	public static FridaDebugger init() {
		FridaNative.INSTANCE.GH_frida_init();
		return new FridaDebugger(FridaNative.INSTANCE.GH_frida_device_manager_new());
	}
	
	public static FridaTarget createTarget(FridaDebugger d) {
		Pointer deviceManager = d.getPointer();
		FridaError err = new FridaError();
		Pointer localDevice = FridaNative.INSTANCE.GH_frida_device_manager_find_device_by_type_sync(deviceManager, new NativeLong(0), new NativeLong(10), null, err.error);
		if (localDevice == null) {
			Msg.error(d, err);
			return null;
		}
		return new FridaTarget(localDevice);
	}
	
	public static List<FridaTarget> enumerateDevices(FridaDebugger d) {
		Pointer deviceManager = d.getPointer();
		FridaError err = new FridaError();
		Pointer deviceList = FridaNative.INSTANCE.GH_frida_device_manager_enumerate_devices_sync(deviceManager, null, err.error);
		if (deviceList == null) {
			Msg.error(d, err);
			return null;
		}
		Integer numDevices = FridaNative.INSTANCE.GH_frida_device_list_size(deviceList);
		List<FridaTarget> targetList = new ArrayList<>(numDevices);
		for (int i = 0; i != numDevices; i++) {
			Pointer device = FridaNative.INSTANCE.GH_frida_device_list_get(deviceList, i);
		    String name = FridaNative.INSTANCE.GH_frida_device_get_name(device);
		    FridaTarget t = new FridaTarget(device);
		    t.setName(name);
		    targetList.add(t);
		}
		return targetList;
	}
	
	public static List<FridaProcess> enumerateProcesses(FridaTarget t) {
		Pointer device = t.getPointer();
		FridaError err = new FridaError();
		Pointer list = FridaNative.INSTANCE.GH_frida_device_enumerate_processes_sync(device, null, null, err.error);
		if (list == null) {
			Msg.error(t, err);
			return null;
		}
		Integer numProcesses = FridaNative.INSTANCE.GH_frida_process_list_size(list);
		List<FridaProcess> processList = new ArrayList<>(numProcesses);
		for (int i = 0; i != numProcesses; i++) {
			Pointer process = FridaNative.INSTANCE.GH_frida_process_list_get(list, i);
		    NativeLong pid = FridaNative.INSTANCE.GH_frida_process_get_pid(process);
		    String name = FridaNative.INSTANCE.GH_frida_process_get_name(process);
		    FridaProcess p = new FridaProcess(process, pid);
		    p.setName(name);
		    processList.add(p);
		}
		return processList;
	}
	
	public static List<FridaProcess> enumerateApplications(FridaTarget t) {
		Pointer device = t.getPointer();
		FridaError err = new FridaError();
		Pointer list = FridaNative.INSTANCE.GH_frida_device_enumerate_applications_sync(device, null, null, err.error);
		if (list == null) {
			Msg.error(t, err);
			return null;
		}
		Integer numApplications = FridaNative.INSTANCE.GH_frida_process_list_size(list);
		List<FridaProcess> processList = new ArrayList<>(numApplications);
		for (int i = 0; i != numApplications; i++) {
			Pointer application = FridaNative.INSTANCE.GH_frida_application_list_get(list, i);
		    NativeLong pid = FridaNative.INSTANCE.GH_frida_application_get_pid(application);
		    String name = FridaNative.INSTANCE.GH_frida_application_get_name(application);
		    String identifier = FridaNative.INSTANCE.GH_frida_application_get_identifier(application);
		    FridaProcess p = new FridaProcess(application, pid);
		    p.setName(name);
		    p.setIdentifier(identifier);
		    processList.add(p);
		}
		return processList;
	}
	
	public static FridaSession attach(FridaTarget t, NativeLong pid, FridaError err) {
		Pointer localDevice = t.getPointer();
		FridaNative.GError.ByReference ref = new FridaNative.GError.ByReference();
		Pointer session = FridaNative.INSTANCE.GH_frida_device_attach_sync(localDevice, pid, FridaEng.FRIDA_REALM_NATIVE, null, ref);
		if (session == null) {
			Msg.error(t, ref);			
			return null;
		}
		Pointer process = FridaNative.INSTANCE.GH_frida_device_get_process_by_pid_sync(localDevice, pid, null, null, err.error);
		if (process == null) {
			Msg.error(t, err);			
			return null;
		}
		FridaProcess p = new FridaProcess(process, pid);
		FridaSession s = new FridaSession(session, p);
		p.setSession(s);
		s.setTarget(t);
		t.setSession(s);
		return s;
	}

	public static FridaSession spawn(FridaTarget t, String fileName, FridaError err) {
		Pointer localDevice = t.getPointer();
		NativeLong pid = FridaNative.INSTANCE.GH_frida_device_spawn_sync(localDevice, fileName, FridaEng.FRIDA_REALM_NATIVE, null, err.error);
		if (!err.success()) {
			Msg.error(t, err);			
			return null;
		}
		return attach(t, pid, err);
	}

	public static void resume(FridaTarget t, NativeLong pid, FridaError err) {
		Pointer localDevice = t.getPointer();
		FridaNative.INSTANCE.GH_frida_device_resume_sync(localDevice, pid, null, err.error);
		if (!err.success()) {
			Msg.error(t, err);			
		}
	}

	public static void kill(FridaTarget t, NativeLong pid, FridaError err) {
		Pointer localDevice = t.getPointer();
		FridaNative.INSTANCE.GH_frida_device_kill_sync(localDevice, pid, null, err.error);
		if (!err.success()) {
			Msg.error(t, err);			
		}
	}

	public static void detach(FridaSession s, FridaError err) {
		Pointer session = s.getPointer();
		FridaNative.INSTANCE.GH_frida_session_detach_sync(session, null, err.error);
		if (!err.success()) {
			Msg.error(s, err);			
		}
	}

	public static void resume(FridaSession s, FridaError err) {
		Pointer session = s.getPointer();
		FridaNative.INSTANCE.GH_frida_session_resume_sync(session, null, err.error);
		if (!err.success()) {
			Msg.error(s, err);			
		}
	}


	public static NativeLong connectSignal(FridaScript s, String signal, FridaNative.MessageCallback cb, Pointer userData) {
		Pointer script = s.getPointer();
		return FridaNative.INSTANCE.GH_g_signal_connect_data(script, signal, cb, userData, null, new NativeLong(0));
	}
	
	public static void disconnectSignal(FridaScript s, NativeLong signal) {
		Pointer script = s.getPointer();
		FridaNative.INSTANCE.GH_g_signal_handler_disconnect(script, signal);
	}

	public static NativeLong createSignal(String signal) {
		return FridaNative.INSTANCE.GH_g_signal_new(
			signal, 
			FridaNative.INSTANCE.GH_frida_bus_session_get_type(), 	// type_from_class
			new NativeLong(2), 		// G_SIGNAL_RUN_LAST
			new NativeLong(0), 		// class_ofset
			null, 					// accumulator
			null, 					// accu_data
			null, 					// closure
			new NativeLong(1), 		// G_TYPE_NULL
			new NativeLong(1), 		// 1 param
			new NativeLong(16)  	// G_TYPE_STRING
		);
	}

	public static void emitSignal(FridaSession s, String signal) {
		Pointer script = s.getPointer();
		FridaNative.INSTANCE.GH_g_signal_emit_by_name(script, signal);
	}

	public static NativeLong getBusType() {
		return FridaNative.INSTANCE.GH_frida_bus_session_get_type();
	}



	public static FridaScript createScript(FridaSession s, String commands, Pointer options) {
		if (s == null) {
			Msg.error(s, "null session");
			return null;
		}
		Pointer session = s.getPointer();
		FridaError err = new FridaError();
		Pointer script = FridaNative.INSTANCE.GH_frida_session_create_script_sync(session, commands, options, null, err.error);
		if (script == null) {
			Msg.error(s, "Unable to create script: " + commands);
			return null;
		}
		return new FridaScript(script);
	}

	public static void unref(FridaScript s) {
		Pointer script = s.getPointer();
		FridaNative.INSTANCE.GH_frida_unref(script);
	}


	public static void loadScript(FridaScript s) {
		Pointer script = s.getPointer();
		FridaError err = new FridaError();
		FridaNative.INSTANCE.GH_frida_script_load_sync(script, null, err.error);
		if (!err.success()) {
			Msg.error(s, err);
		}
	}

	public static void unloadScript(FridaScript s) {
		Pointer script = s.getPointer();
		FridaError err = new FridaError();
		FridaNative.INSTANCE.GH_frida_script_unload_sync(script, null, err.error);
		if (!err.success()) {
			Msg.error(s, err);
		}
	}

	public static Pointer createOptions(String name) {
		Pointer options = FridaNative.INSTANCE.GH_frida_script_options_new();
		FridaNative.INSTANCE.GH_frida_script_options_set_name(options, name);
		FridaNative.INSTANCE.GH_frida_script_options_set_runtime(options, new NativeLong(0L));
		return options;
	}

	public static void enableDebugger(FridaSession s, NativeLong port) {
		Pointer session = s.getPointer();
		FridaError err = new FridaError();
		FridaNative.INSTANCE.GH_frida_session_enable_debugger_sync(session, port, null, err.error);
		if (!err.success()) {
			Msg.error(s, err);
		}
	}



}
