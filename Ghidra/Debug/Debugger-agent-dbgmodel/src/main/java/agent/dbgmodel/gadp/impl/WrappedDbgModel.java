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
package agent.dbgmodel.gadp.impl;

import java.nio.ByteBuffer;
import java.util.*;

import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.COM.COMException;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugRunningProcess.Description;
import agent.dbgeng.dbgeng.DebugRunningProcess.Description.ProcessDescriptionFlags;
import agent.dbgeng.dbgeng.DebugValue.*;
import agent.dbgmodel.dbgmodel.bridge.HostDataModelAccess;
import agent.dbgmodel.dbgmodel.debughost.*;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.DebugRunningProcessImpl;
import agent.dbgmodel.impl.dbgmodel.bridge.HDMAUtil;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import ghidra.comm.util.BitmaskSet;

public class WrappedDbgModel
		implements DebugClient, DebugSystemObjects, DebugRegisters, DebugDataSpaces, DebugSymbols {

	private HDMAUtil util;
	private DebugClient client;
	private HashMap<Object, String> map = new HashMap<Object, String>();
	private boolean USE_CLIENT = false;

	//private boolean USE_CLIENT = true;

	public WrappedDbgModel(HostDataModelAccess access) {
		util = new HDMAUtil(access);
		client = access.getClient();
		System.err.println(">>>>>>>>>>>>  USING WRAPPED DBGMODEL  <<<<<<<<<<<<<<");
	}

	public DebugClient getClient() {
		return this;
	}

	// Used to get ExitTime/Status for threads
	@Override
	public DebugAdvanced getAdvanced() {
		return client.getAdvanced();
	}

	// Used for control, I/O, breakpoints
	@Override
	public DebugControl getControl() {
		return client.getControl();
	}

	// Used to enumerate/read-write regions
	@Override
	public DebugDataSpaces getDataSpaces() {
		return this;
	}

	// Used to enumerate registers
	@Override
	public DebugRegisters getRegisters() {
		return this;
	}

	// Used to enumerate threads/processes
	@Override
	public DebugSystemObjects getSystemObjects() {
		return this;
	}

	// Used to enumerate symbols
	@Override
	public DebugSymbols getSymbols() {
		return this;
	}

	public Map<String, ModelObject> getAttributes(List<String> path) {
		return getUtil().getAttributes(path);
	}

	public List<ModelObject> getElements(List<String> path) {
		return getUtil().getElements(path);
	}

	public ModelObject getMethod(List<String> path) {
		return getUtil().getMethod(path);
	}

	@Override
	public void attachProcess(DebugServerId si, long processId,
			BitmaskSet<DebugAttachFlags> attachFlags) {
		client.attachProcess(si, processId, attachFlags);
	}

	@Override
	public void createProcess(DebugServerId si, String commandLine,
			BitmaskSet<DebugCreateFlags> createFlags) {
		client.createProcess(si, commandLine, createFlags);
	}

	@Override
	public void createProcessAndAttach(DebugServerId si, String commandLine,
			BitmaskSet<DebugCreateFlags> createFlags, int processId,
			BitmaskSet<DebugAttachFlags> attachFlags) {
		client.createProcessAndAttach(si, commandLine, createFlags, processId, attachFlags);
	}

	@Override
	public void abandonCurrentProcess() {
		client.abandonCurrentProcess();
	}

	@Override
	public void startServer(String options) {
		client.startServer(options);
	}

	@Override
	public void waitForProcessServerEnd(int timeout) {
		client.waitForProcessServerEnd(timeout);
	}

	@Override
	public void terminateCurrentProcess() {
		client.terminateCurrentProcess();
	}

	@Override
	public void detachCurrentProcess() {
		client.detachCurrentProcess();
	}

	@Override
	public void connectSession(int flags) {
		client.connectSession(flags);
	}

	@Override
	public void endSession(DebugEndSessionFlags flags) {
		client.endSession(flags);
	}

	public HDMAUtil getUtil() {
		return util;
	}

	@Override
	public DebugClient createClient() {
		return client;
	}

	@Override
	public void endSessionReentrant() {
		client.endSessionReentrant();
	}

	@Override
	public DebugServerId getLocalServer() {
		return client.getLocalServer();
	}

	@Override
	public void attachKernel(long flags, String options) {
		client.attachKernel(flags, options);
	}

	@Override
	public void startProcessServer(String options) {
		client.startProcessServer(options);
	}

	@Override
	public DebugServerId connectProcessServer(String options) {
		return client.connectProcessServer(options);
	}

	@Override
	public boolean dispatchCallbacks(int timeout) {
		return client.dispatchCallbacks(timeout);
	}

	@Override
	public void flushCallbacks() {
		client.flushCallbacks();
	}

	@Override
	public void exitDispatch(DebugClient client) {
		client.exitDispatch(client);
	}

	@Override
	public void setInputCallbacks(DebugInputCallbacks cb) {
		client.setInputCallbacks(cb);
	}

	@Override
	public void setOutputCallbacks(DebugOutputCallbacks cb) {
		client.setOutputCallbacks(cb);
	}

	@Override
	public void setEventCallbacks(DebugEventCallbacks cb) {
		client.setEventCallbacks(cb);
	}

	@Override
	public Description getProcessDescription(DebugServerId si, int systemId,
			BitmaskSet<ProcessDescriptionFlags> flags) {
		return client.getProcessDescription(si, systemId, flags);
	}

	@Override
	public void openDumpFileWide(String fileName) {
		client.openDumpFileWide(fileName);
	}

	// DATA SPACES INTERFACE

	@Override
	public int readVirtual(long offset, ByteBuffer buf, int remaining) {
		DebugHostContext currentContext = getUtil().getCurrentContext();
		DebugHost host = getUtil().getHost();
		ULONGLONG ulOffset = new ULONGLONG(offset);
		LOCATION base = new LOCATION(ulOffset);
		DebugHostMemory1 memory = host.asMemory();
		return (int) memory.readBytes(currentContext, base, buf, remaining);
	}

	@Override
	public int writeVirtual(long offset, ByteBuffer buf, int remaining) {
		// UNTESTED
		DebugHostContext currentContext = getUtil().getCurrentContext();
		DebugHost host = getUtil().getHost();
		ULONGLONG ulOffset = new ULONGLONG(offset);
		LOCATION base = new LOCATION(ulOffset);
		DebugHostMemory1 memory = host.asMemory();
		return (int) memory.writeBytes(currentContext, base, buf, remaining);
	}

	@Override
	public int readVirtualUncached(long offset, ByteBuffer into, int len) {
		return readVirtual(offset, into, len);
	}

	@Override
	public int writeVirtualUncached(long offset, ByteBuffer from, int len) {
		return readVirtual(offset, from, len);
	}

	// TODO what follows is untested

	@Override
	public int readPhysical(long offset, ByteBuffer buf, int remaining) {
		return client.getDataSpaces().readPhysical(offset, buf, remaining);
	}

	@Override
	public int writePhysical(long offset, ByteBuffer buf, int remaining) {
		return client.getDataSpaces().writePhysical(offset, buf, remaining);
	}

	@Override
	public int readControl(int processor, long offset, ByteBuffer buf, int remaining) {
		return client.getDataSpaces().readControl(processor, offset, buf, remaining);
	}

	@Override
	public int writeControl(int processor, long offset, ByteBuffer buf, int remaining) {
		return client.getDataSpaces().writeControl(processor, offset, buf, remaining);
	}

	@Override
	public int readBusData(int busDataType, int busNumber, int slotNumber, long offset,
			ByteBuffer buf, int remaining) {
		return client.getDataSpaces()
				.readBusData(busDataType, busNumber, slotNumber, offset, buf, remaining);
	}

	@Override
	public int writeBusData(int busDataType, int busNumber, int slotNumber, long offset,
			ByteBuffer buf, int remaining) {
		return client.getDataSpaces()
				.writeBusData(busDataType, busNumber, slotNumber, offset, buf, remaining);
	}

	@Override
	public int readIo(int interfaceType, int busNumber, int addressSpace, long offset,
			ByteBuffer buf, int remaining) {
		return client.getDataSpaces()
				.readIo(interfaceType, busNumber, addressSpace, offset, buf, remaining);
	}

	@Override
	public int writeIo(int interfaceType, int busNumber, int addressSpace, long offset,
			ByteBuffer buf, int remaining) {
		return client.getDataSpaces()
				.writeIo(interfaceType, busNumber, addressSpace, offset, buf, remaining);
	}

	@Override
	public long readMsr(int msr) {
		return client.getDataSpaces().readMsr(msr);
	}

	@Override
	public void writeMsr(int msr, long value) {
		client.getDataSpaces().writeMsr(msr, value);
	}

	@Override
	public int readDebuggerData(int offset, ByteBuffer buf, int remaining) {
		DebugHostContext currentContext = getUtil().getCurrentContext();
		DebugHost host = getUtil().getHost();
		ULONGLONG ulOffset = new ULONGLONG(offset);
		LOCATION base = new LOCATION(ulOffset);
		DebugHostMemory1 memory = host.asMemory();
		return (int) memory.readBytes(currentContext, base, buf, remaining);
	}

	@Override
	public DebugMemoryBasicInformation queryVirtual(long offset) {
		return client.getDataSpaces().queryVirtual(offset);
	}

	// REGISTERS INTERFACE

	public DebugRegisterDescription getRegisterDescription(int i) {
		return client.getRegisters().getDescription(i);
		/*
		if (USE_CLIENT) {
			System.err.println("getRegisterDescription");
			return client.getRegisters().getDescription(i);
		}
		*/
		/*
		Map<String, ModelObject> registerMap = getRegisterMap();
		Object[] array = registerMap.keySet().toArray();
		if (i > array.length) {
			DebugRegisterDescription description = client.getRegisters().getDescription(i);
			System.err.println(description.name + " not found");
			return null;
		}
		String regname = (String) array[i];
		ModelObject register = registerMap.get(regname);
		DebugRegisterDescription drp = new DebugRegisterDescription(regname, i, getDVType(register),
			new BitmaskSet<>(DebugRegisterFlags.class, 0), 0, 0, 0, 0);
		return drp;
		*/
	}

	public Set<DebugRegisterDescription> getAllRegisterDescriptions() {
		return client.getRegisters().getAllDescriptions();
		/*
		if (USE_CLIENT) {
			System.err.println("getAllRegisterDescriptions");
			return client.getRegisters().getAllDescriptions();
		}
		*/
		/*
		Set<DebugRegisterDescription> set = new HashSet<DebugRegisters.DebugRegisterDescription>();
		Map<String, ModelObject> registerMap = getRegisterMap();
		Object[] array = registerMap.keySet().toArray();
		for (int i = 0; i < array.length; i++) {
			String regname = (String) array[i];
			if (regname == null) {
				continue;
			}
			ModelObject register = registerMap.get(regname);
			DebugRegisterDescription drp = new DebugRegisterDescription(regname, i,
				getDVType(register), new BitmaskSet<>(DebugRegisterFlags.class, 0), 0, 0, 0, 0);
			set.add(drp);
		}
		return set;
		*/
	}

	/*
	public void setRegisterValue(Entry<String, byte[]> ent) {
		System.err.println("setRegisterValue");
		Map<String, ModelObject> registerMap = getRegisterMap();
		ModelObject register = registerMap.get(ent.getKey());
		DebugValue value = decodeBytes(register, ent.getValue());
		client.getRegisters().setValueByName(ent.getKey(), value);
	}
	*/

	@Override
	public int getNumberRegisters() {
		return client.getRegisters().getNumberRegisters();
		//return getRegisterMap().size();
	}

	@Override
	public DebugRegisterDescription getDescription(int registerNumber) {
		return getRegisterDescription(registerNumber);
	}

	@Override
	public int getIndexByName(String name) {
		return client.getRegisters().getIndexByName(name);
		/*
		if (USE_CLIENT) {
			System.err.println("getAllRegisterDescriptions");
			return client.getRegisters().getIndexByName(name);
		}
		*/
		/*
		TreeMap<String, ModelObject> registerMap = (TreeMap) getRegisterMap();
		Object[] array = registerMap.keySet().toArray();
		for (int i = 0; i < array.length; i++) {
			String key = (String) array[i];
			if (key.equals(name)) {
				return i;
			}
		}
		return -1;
		*/
	}

	@Override
	public DebugValue getValueByName(String name) {
		return client.getRegisters().getValueByName(name);
		//TreeMap<String, ModelObject> registerMap = (TreeMap) getRegisterMap();
		//ModelObject obj = registerMap.get(name);
		//return getDebugValue(obj);
	}

	@Override
	public DebugValue getValue(int index) {
		return client.getRegisters().getValue(index);
		/*
		if (USE_CLIENT) {
			System.err.println("getAllRegisterDescriptions");
			return client.getRegisters().getValue(index);
		}
		*/
		/*
		TreeMap<String, ModelObject> registerMap = (TreeMap) getRegisterMap();
		Object[] array = registerMap.values().toArray();
		if (index >= 0 && index < array.length) {
			ModelObject obj = (ModelObject) array[index];
			return getDebugValue(obj);
		}
		return null;
		*/
	}

	@Override
	public Map<Integer, DebugValue> getValues(DebugRegisterSource source,
			Collection<Integer> indices) {
		return client.getRegisters().getValues(source, indices);
		/*
		if (USE_CLIENT) {
			System.err.println("getAllRegisterDescriptions");
			return client.getRegisters().getValues(source, indices);
		}
		*/
		/*
		TreeMap<String, ModelObject> registerMap = (TreeMap) getRegisterMap();
		Object[] array = registerMap.keySet().toArray();
		Map<Integer, DebugValue> registers = new TreeMap<Integer, DebugValue>();
		for (Integer index : indices) {
			String key = (String) array[index];
			ModelObject obj = registerMap.get(key);
			registers.put(index, getDebugValue(obj));
		}
		return registers;
		*/
	}

	@Override
	public void setValueByName(String name, DebugValue value) {
		setValue(getIndexByName(name), value);
	}

	@Override
	public void setValue(int index, DebugValue value) {
		client.getRegisters().setValue(index, value);
	}

	@Override
	public void setValues(DebugRegisterSource source, Map<Integer, DebugValue> values) {
		client.getRegisters().setValues(source, values);
	}

	// SYSTEM OBJECT INTERFACE

	public List<DebugThreadId> getThreadIds() {
		List<DebugThreadId> ids = null;
		/*
		if (USE_CLIENT) {
			System.err.println("getThreadIds");
			ids = client.getSystemObjects().getThreads();
			return ids;
		}
		*/
		ModelObject currentSession = getUtil().getCurrentSession();
		ModelObject currentProcess = getUtil().getCurrentProcess();
		String pid = getUtil().getCtlId(currentProcess);
		List<ModelObject> runningThreads = getUtil().getRunningThreads(currentSession, pid);
		ids = new ArrayList<DebugThreadId>();
		for (ModelObject t : runningThreads) {
			String tid = getUtil().getCtlId(t);
			ids.add(tid2dti(tid));
		}
		return ids;
	}

	public List<DebugProcessId> getProcessIds() {
		/*
		if (USE_CLIENT) {
			System.err.println("getProcessIds");
			return client.getSystemObjects().getProcesses();
		}
		*/
		// TODO: What follow is problematic.  SO.getProcesses uses SO.GetNumberProcesses
		// and GetProcessIdsByIndex, which return the processes being debugged, not the
		// system process list. Using the system process list and calling getProcessIdBySystemID
		// triggers unsupported interface COM exceptions
		List<DebugProcessId> ids = new ArrayList<DebugProcessId>();
		List<DebugRunningProcess> procs = getRunningProcesses(sid2dsi());
		for (DebugRunningProcess p : procs) {
			try {
				ids.add(pid2dpi("0x" + Integer.toHexString(p.getSystemId())));
			}
			catch (COMException e) {
				System.err.println(p.getSystemId());
			}
		}
		return ids;
	}

	@Override
	public void setCurrentSystemId(DebugSessionId dpi) {
		client.getSystemObjects().setCurrentSystemId(dpi);
		/*
		if (USE_CLIENT) {
			System.err.println("setCurrentProcess");
			client.getSystemObjects().setCurrentProcessId(dpi);
			return;
		}
		*//* DOESN'T WORK
			String pid = obj2id(dpi);
			ModelObject currentProcess = util.getCurrentProcess();
			util.setCurrentProcess(currentProcess, pid);
			*/
	}

	@Override
	public void setCurrentProcessId(DebugProcessId dpi) {
		client.getSystemObjects().setCurrentProcessId(dpi);
		/*
		if (USE_CLIENT) {
			System.err.println("setCurrentProcess");
			client.getSystemObjects().setCurrentProcessId(dpi);
			return;
		}
		*//* DOESN'T WORK
			String pid = obj2id(dpi);
			ModelObject currentProcess = util.getCurrentProcess();
			util.setCurrentProcess(currentProcess, pid);
			*/
	}

	@Override
	public void setCurrentThreadId(DebugThreadId dti) {
		DebugSystemObjects so = client.getSystemObjects();
		DebugThreadId currentThreadId = so.getCurrentThreadId();
		if (dti.id != currentThreadId.id) {
			so.setCurrentThreadId(dti);
		}
		/*
		if (USE_CLIENT) {
			System.err.println("setCurrentThread");
			client.getSystemObjects().setCurrentThreadId(dti);
			return;
		}
		*//* DOESN'T WORK
			String tid = obj2id(dti);
			ModelObject currentThread = util.getCurrentThread();
			util.setCurrentThread(currentThread, tid);
			*/
	}

	@Override
	public DebugSessionId getCurrentSystemId() {
		/*
		if (USE_CLIENT) {
			System.err.println("getCurrentSystemId");
			return client.getSystemObjects().getCurrentSystemId();
		}
		*/
		return client.getSystemObjects().getCurrentSystemId();
	}

	@Override
	public DebugProcessId getCurrentProcessId() {
		/*
		if (USE_CLIENT) {
			System.err.println("getCurrentProcessId");
			return client.getSystemObjects().getCurrentProcessId();
		}
		*/
		ModelObject currentProcess = getUtil().getCurrentProcess();
		DebugProcessId dpi = client.getSystemObjects().getCurrentProcessId();
		if (currentProcess != null) {
			String id = getUtil().getCtlId(currentProcess);
			addObj(dpi, id);
		}
		return dpi;
	}

	@Override
	public DebugThreadId getCurrentThreadId() {
		/*
		if (USE_CLIENT) {
			System.err.println("getCurrentThreadId");
			return client.getSystemObjects().getCurrentThreadId();
		}
		*/
		ModelObject currentThread = getUtil().getCurrentThread();
		DebugThreadId dti = client.getSystemObjects().getCurrentThreadId();
		if (currentThread != null) {
			String id = getUtil().getCtlId(currentThread);
			addObj(dti, id);
		}
		return dti;
	}

	@Override
	public DebugProcessId getProcessIdByHandle(long handle) {
		// "Handle" key exists for processes, but not threads currently
		return client.getSystemObjects().getProcessIdByHandle(handle);
	}

	@Override
	public DebugThreadId getThreadIdByHandle(long handle) {
		// "Handle" key exists for processes, but not threads currently
		return client.getSystemObjects().getThreadIdByHandle(handle);
	}

	@Override
	public DebugSessionId getEventSystem() {
		/*
		if (USE_CLIENT) {
			System.err.println("getEventProcess");
			return client.getSystemObjects().getEventProcess();
		}
		*/
		return client.getSystemObjects().getEventSystem();
		//return getCurrentProcessId();
	}

	@Override
	public DebugProcessId getEventProcess() {
		/*
		if (USE_CLIENT) {
			System.err.println("getEventProcess");
			return client.getSystemObjects().getEventProcess();
		}
		*/
		return client.getSystemObjects().getEventProcess();
		//return getCurrentProcessId();
	}

	@Override
	public DebugThreadId getEventThread() {
		/*
		if (USE_CLIENT) {
			System.err.println("getEventThread");
			return client.getSystemObjects().getEventThread();
		}
		*/
		return client.getSystemObjects().getEventThread();
		//return getCurrentThreadId();
	}

	@Override
	public List<DebugRunningProcess> getRunningProcesses(DebugServerId si) {
		/*
		if (USE_CLIENT) {
			System.err.println("getRunningProcesses");
			return client.getRunningProcesses(si);
		}
		*/
		List<ModelObject> processes = getUtil().getRunningProcesses(obj2id(si));
		List<DebugRunningProcess> result = new ArrayList<>(processes.size());
		for (ModelObject child : processes) {
			String pid = getUtil().getCtlId(child);
			result.add(new DebugRunningProcessImpl(pid, child, si));
		}
		return result;
	}

	@Override
	public int getCurrentThreadSystemId() {  // used by impl
		return client.getSystemObjects().getCurrentThreadSystemId();
		//return getCurrentThreadId().id;
	}

	@Override
	public int getCurrentProcessSystemId() {  // used by impl
		return client.getSystemObjects().getCurrentProcessSystemId();
		//return getCurrentProcessId().id;
	}

	@Override
	public int getNumberThreads() {  // used by dso
		return client.getSystemObjects().getNumberThreads();
	}

	@Override
	public List<DebugThreadId> getThreads(int start, int count) { // used by dso
		return client.getSystemObjects().getThreads(start, count);
	}

	@Override
	public int getNumberProcesses() {  // used by dso
		return client.getSystemObjects().getNumberProcesses();
	}

	@Override
	public List<DebugProcessId> getProcesses(int start, int count) {  // used by dso
		return client.getSystemObjects().getProcesses(start, count);
	}

	@Override
	public int getNumberSystems() {  // used by dso
		return client.getSystemObjects().getNumberSystems();
	}

	@Override
	public List<DebugSessionId> getSystems(int start, int count) {  // used by dso
		return client.getSystemObjects().getSystems(start, count);
	}

	@Override
	public DebugThreadId getThreadIdBySystemId(int systemId) {  // used by this
		return client.getSystemObjects().getThreadIdBySystemId(systemId);
	}

	@Override
	public DebugProcessId getProcessIdBySystemId(int systemId) {  // used by this
		return client.getSystemObjects().getProcessIdBySystemId(systemId);
	}

	@Override
	public int getTotalNumberThreads() {  // unused
		return client.getSystemObjects().getTotalNumberThreads();
	}

	// SYMBOLS INTERFACE

	public List<DebugHostModule1> getDebugHostModules() {
		DebugHostSymbols symbols = getUtil().getHost().asSymbols();
		DebugHostSymbolEnumerator enumerator =
			symbols.enumerateModules(getUtil().getCurrentContext());
		List<DebugHostModule1> list = new ArrayList<DebugHostModule1>();
		DebugHostSymbol1 next;
		while ((next = enumerator.getNext()) != null) {
			list.add(next.asModule());
		}
		return list;
	}

	public List<DebugModule> getModuleList() {
		return getUtil().getModuleList();
	}

	@Override
	public int getNumberLoadedModules() {
		return getModuleList().size();
	}

	@Override
	public int getNumberUnloadedModules() {
		return client.getSymbols().getNumberUnloadedModules();
	}

	@Override
	public DebugModule getModuleByIndex(int index) {
		List<DebugModule> modules = getModuleList();
		return modules.get(index);
	}

	@Override
	public DebugModule getModuleByModuleName(String name, int startIndex) {
		List<DebugModule> modules = getModuleList();
		for (DebugModule module : modules) {
			String moduleName = module.getName(null);
			if (moduleName.equals(name)) {
				return module;
			}
		}
		System.err.println(name + " not found");
		return null;
	}

	@Override
	public DebugModule getModuleByOffset(long offset, int startIndex) {
		List<DebugModule> modules = getModuleList();
		long min = Long.MAX_VALUE;
		DebugModule ret = null;
		for (DebugModule module : modules) {
			long baseAddress = module.getBase();
			if (offset >= baseAddress && baseAddress < min) {
				min = baseAddress;
				ret = module;
			}
		}
		return ret;
	}

	@Override
	public DebugModuleInfo getModuleParameters(int count, int startIndex) {
		return client.getSymbols().getModuleParameters(count, startIndex);
	}

	@Override
	public Iterable<DebugSymbolName> iterateSymbolMatches(String pattern) {
		return client.getSymbols().iterateSymbolMatches(pattern);
	}

	@Override
	public List<DebugSymbolId> getSymbolIdsByName(String pattern) {
		return client.getSymbols().getSymbolIdsByName(pattern);
	}

	@Override
	public DebugSymbolEntry getSymbolEntry(DebugSymbolId id) {
		return client.getSymbols().getSymbolEntry(id);
	}

	@Override
	public String getSymbolPath() {
		return client.getSymbols().getSymbolPath();
	}

	@Override
	public void setSymbolPath(String path) {
		client.getSymbols().setSymbolPath(path);
	}

	@Override
	public int getSymbolOptions() {
		return client.getSymbols().getSymbolOptions();
	}

	@Override
	public void setSymbolOptions(int options) {
		client.getSymbols().setSymbolOptions(options);
	}

	// UTILITY METHODS

	private DebugServerId sid2dsi() {
		DebugServerId dsi = new DebugServerId(0);
		addObj(dsi, "0");
		return dsi;
	}

	private DebugProcessId pid2dpi(String id) {
		if (!id.startsWith("0x")) {
			id = "0x" + id;
		}
		int pid = Integer.decode(id);
		if (pid == 0) {
			return new DebugProcessId(-1);
		}
		DebugProcessId dpi = client.getSystemObjects().getProcessIdBySystemId(pid);
		addObj(dpi, id);
		return dpi;
	}

	private DebugThreadId tid2dti(String id) {
		if (!id.startsWith("0x")) {
			id = "0x" + id;
		}
		int tid = Integer.decode(id);
		DebugThreadId dti = client.getSystemObjects().getThreadIdBySystemId(tid);
		addObj(dti, id);
		return dti;
	}

	private void addObj(Object obj, String id) {
		if (obj == null || id == null) {
			System.err.println("attempt to add null object");
		}
		map.put(obj, id);
	}

	private String obj2id(Object obj) {
		String id = map.get(obj);
		return id;
	}

	public DebugValue getDebugValue(ModelObject register) {
		DebugValue dv = null;
		Object value = register.getValue();
		if (value instanceof Short) {
			dv = new DebugInt16Value(((Short) value).shortValue());
		}
		else if (value instanceof Integer) {
			dv = new DebugInt32Value(((Integer) value).intValue());
		}
		else if (value instanceof Long) {
			dv = new DebugInt64Value(((Long) value).longValue());
		}
		return dv;
	}

	public byte[] encodeAsBytes(ModelObject register) {
		DebugValue dv = null;
		Object value = register.getValue();
		if (value instanceof Short) {
			Short lval = (Short) value;
			dv = new DebugInt16Value(lval);
		}
		else if (value instanceof Integer) {
			Integer lval = (Integer) value;
			dv = new DebugInt32Value(lval);
		}
		else if (value instanceof Long) {
			Long lval = (Long) value;
			dv = new DebugInt64Value(lval);
		}
		else {
			return new byte[0];
		}
		return dv.encodeAsBytes();
	}

	private DebugValue decodeBytes(ModelObject register, byte[] bytes) {
		DebugValue dv = null;
		Object value = register.getValue();
		if (value instanceof Short) {
			dv = new DebugInt16Value(bytes);
		}
		else if (value instanceof Integer) {
			dv = new DebugInt32Value(bytes);
		}
		else if (value instanceof Long) {
			dv = new DebugInt64Value(bytes);
		}
		return dv;
	}

	private DebugValueType getDVType(ModelObject register) {
		Object value = register.getValue();
		if (value instanceof Short) {
			return DebugValueType.INT16;
		}
		else if (value instanceof Integer) {
			return DebugValueType.INT32;
		}
		else if (value instanceof Long) {
			return DebugValueType.INT64;
		}
		return DebugValueType.INVALID;
	}

	@Override
	public int getCurrentScopeFrameIndex() {
		return client.getSymbols().getCurrentScopeFrameIndex();
	}

	@Override
	public void setCurrentScopeFrameIndex(int index) {
		client.getSymbols().setCurrentScopeFrameIndex(index);
	}

}
