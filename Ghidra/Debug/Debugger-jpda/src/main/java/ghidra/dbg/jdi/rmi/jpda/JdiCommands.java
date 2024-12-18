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
package ghidra.dbg.jdi.rmi.jpda;

import static ghidra.dbg.jdi.rmi.jpda.JdiConnector.*;

import java.io.IOException;
import java.io.PrintStream;
import java.lang.ProcessHandle.Info;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.channels.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;
import java.util.stream.IntStream;

import org.apache.commons.lang3.StringUtils;

import com.sun.jdi.*;
import com.sun.jdi.Method;
import com.sun.jdi.Value;
import com.sun.jdi.event.Event;
import com.sun.jdi.request.*;

import ghidra.app.plugin.core.debug.client.tracermi.*;
import ghidra.dbg.jdi.manager.impl.JdiManagerImpl;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.Language;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.trace.model.Lifespan;
import ghidra.util.Msg;

/*
 * Some notes:
 * 		ghidraTracePutX:  batch wrapper around putXxxx
 * 		putX:  generally creates the object and calls putXDetails
 * 		putXDetails:  assumes the object already exists
 * 		putXContainer:  creates one or more objects
 * 		xProxy:  container for exactly one X
 */

class State {

	public RmiClient client;
	public RmiTrace trace;
	RmiTransaction tx;

	public RmiClient requireClient() {
		if (client == null) {
			throw new RuntimeException("Not connected");
		}
		return client;
	}

	public void requireNoClient() {
		if (client != null) {
			client = null;
			throw new RuntimeException("Already connected");
		}
	}

	public void resetClient() {
		client = null;
		resetTrace();
	}

	public RmiTrace requireTrace() {
		if (trace == null) {
			throw new RuntimeException("No trace started");
		}
		return trace;
	}

	public void requireNoTrace() {
		if (trace != null) {
			throw new RuntimeException("Trace already started");
		}
	}

	public void resetTrace() {
		trace = null;
		resetTx();
	}

	public RmiTransaction requireTx() {
		if (tx == null) {
			throw new RuntimeException("No transaction");
		}
		return tx;
	}

	public void requireNoTx() {
		if (tx != null) {
			throw new RuntimeException("Transaction already started");
		}
	}

	public void resetTx() {
		tx = null;
	}

}

public class JdiCommands {

	private JdiConnector connector;
	private JdiManagerImpl jdi;

	public State state;
	private String[] regNames = { "PC", "return_address" };
	public long MAX_REFS = 100;

	public JdiCommands(JdiConnector connector) {
		this.connector = connector;
		this.jdi = connector.getJdi();
		state = new State();
	}

	public void ghidraTraceConnect(String address) {
		state.requireNoClient();
		String[] addr = address.split(":");
		if (addr.length != 2) {
			throw new RuntimeException("Address must be in the form 'host:port'");
		}
		try {
			SocketChannel channel =
				SocketChannel.open(new InetSocketAddress(addr[0], Integer.parseInt(addr[1])));
			state.client = new RmiClient(channel, "jdi");
			state.client.setRegistry(connector.remoteMethodRegistry);
			state.client.negotiate("Connect");
			Msg.out("Connected to " + state.client.getDescription());
		}
		catch (NumberFormatException e) {
			throw new RuntimeException("Port must be numeric");
		}
		catch (IOException e) {
			throw new RuntimeException("Error connecting to " + address + ": " + e);
		}
	}

	public void ghidraTraceListen(String address) {
		// TODO: UNTESTED
		state.requireNoClient();
		String host = "0.0.0.0";
		int port = 0;
		if (address != null) {
			String[] parts = address.split(":");
			if (parts.length == 1) {
				port = Integer.parseInt(parts[0]);
			}
			else {
				host = parts[0];
				port = Integer.parseInt(parts[1]);
			}
		}
		try {
			InetSocketAddress socketAddress = new InetSocketAddress(host, port);
			ServerSocketChannel channel = ServerSocketChannel.open();
			channel.bind(socketAddress);
			Selector selector = Selector.open();
			while (true) {
				selector.select();
				Set<SelectionKey> selKeys = selector.selectedKeys();
				Iterator<SelectionKey> keyIterator = selKeys.iterator();

				while (keyIterator.hasNext()) {
					SelectionKey key = keyIterator.next();
					if (key.isAcceptable()) {
						SocketChannel client = channel.accept();
						state.client = new RmiClient(client, "jdi");
						state.client.setRegistry(connector.remoteMethodRegistry);
						client.configureBlocking(false);
						Msg.out("Connected from " + state.client.getDescription());
					}
				}
				keyIterator.remove();
			}
		}
		catch (NumberFormatException e) {
			throw new RuntimeException("Port must be numeric");
		}
		catch (IOException e) {
			throw new RuntimeException("Error connecting to " + address + ": " + e);
		}
	}

	public void ghidraTraceDisconnect() {
		state.requireClient().close();
		state.resetClient();
	}

	private String computeName() {
		VirtualMachine currentVM = connector.getJdi().getCurrentVM();
		if (currentVM != null) {
			Optional<String> command = currentVM.process().info().command();
			if (command.isPresent()) {
				return "jdi/" + command;
			}
		}
		return "jdi/noname";
	}

	public void startTrace(String name) {
		JdiArch arch = connector.getArch();
		LanguageID language = arch.computeGhidraLanguage();
		CompilerSpecID compiler = arch.computeGhidraCompiler(language);
		state.trace = state.client.createTrace(name, language, compiler);

		state.trace.memoryMapper = arch.computeMemoryMapper();
		state.trace.registerMapper = arch.computeRegisterMapper();

		try (RmiTransaction tx = state.trace.startTx("Create snapshots", false)) {
			state.trace.createRootObject(connector.rootSchema.getContext(),
				connector.rootSchema.getName().toString());
			//activate(null);

			// add the DEFAULT_SECTION
			AddressRange range = connector.defaultRange;
			byte[] bytes = new byte[(int) range.getLength()];
			Arrays.fill(bytes, (byte) 0xFF);
			state.trace.putBytes(range.getMinAddress(), bytes, state.trace.getSnap());
		}
	}

	public void ghidraTraceStart(String name) {
		state.requireClient();
		if (name == null) {
			name = computeName();
		}
		else if (name.contains("/")) {
			name = name.substring(name.lastIndexOf("/"));
		}
		state.requireNoTrace();
		startTrace(name);
	}

	public void ghidraTraceStop() {
		state.requireTrace().close();
		state.resetTrace();
	}

	public void ghidraTraceRestart(String name) {
		state.requireClient();
		if (state.trace != null) {
			state.trace.close();
			state.resetTrace();
		}
		if (name == null) {
			name = computeName();
		}
		startTrace(name);
	}

	public VirtualMachine ghidraTraceCreate(Map<String, String> env) {
		return connector.getJdi().createVM(env);
	}

	public void ghidraTraceInfo() {
		if (state.client == null) {
			Msg.error(this, "Not connected to Ghidra");
			return;
		}
		Msg.info(this, "Connected to " + state.client.getDescription());
		if (state.trace == null) {
			Msg.error(this, "No trace");
		}
		else {
			Msg.info(this, "Trace active");
		}
	}

	public void ghidraTraceInfoLcsp() {
		JdiArch arch = connector.getArch();
		LanguageID language = arch.computeGhidraLanguage();
		CompilerSpecID compiler = arch.computeGhidraCompiler(language);
		Msg.info(this, "Selected Ghidra language: " + language);
		Msg.info(this, "Selected Ghidra compiler: " + compiler);
	}

	public void ghidraTraceTxStart(String description) {
		state.requireNoTx();
		state.tx = state.requireTrace().startTx(description, false);
	}

	public void ghidraTraceTxCommit() {
		state.requireTx().commit();
		state.resetTx();
	}

	public void ghidraTraceTxAbort() {
		RmiTransaction tx = state.requireTx();
		Msg.info(this, "Aborting trace transaction!");
		tx.abort();
		state.resetTx();
	}

	public void ghidraTraceSave() {
		state.requireTrace().save();
	}

	public long ghidraTraceNewSnap(String description) {
		state.requireTx();
		return state.requireTrace().snapshot(description, null, null);
	}

	public void ghidraTraceSetSnap(long snap) {
		state.requireTrace().setSnap(snap);
	}

	public void ghidraTracePutMem(Address address, long length) {
		state.requireTx();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutMem", false)) {
			putMem(address, length, true);
		}
	}

	public void ghidraTracePutMemState(Address address, long length, MemoryState memState) {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutMemState", false)) {
			putMemState(address, length, memState, true);
		}
	}

	public void ghidraTraceDelMem(Address address, long length) {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTraceDelMem", false)) {
			Address mapped = state.trace.memoryMapper.map(address);
			AddressRangeImpl range = new AddressRangeImpl(mapped, mapped.add(length - 1));
			state.trace.deleteBytes(range, state.trace.getSnap());
		}
	}

	public void ghidraTracePutReg(StackFrame frame) {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutReg", false)) {
			putReg(frame);
		}
	}

	public void ghidraTraceDelReg(StackFrame frame) {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTraceDelReg", false)) {
			String ppath = getPath(frame);
			if (ppath == null) {
				Msg.error(this, "Null path for " + frame);
				return;
			}
			String path = ppath + ".Registers";
			state.trace.deleteRegisters(path, regNames, state.trace.getSnap());
		}
	}

	public void ghidraTraceCreateObj(String path) {
		state.requireTx();
		try (RmiTransaction tx = state.trace.startTx("ghidraTraceCreateObj", false)) {
			createObject(path);
		}
	}

	public void ghidraTraceInsertObj(String path) {
		state.requireTx();
		try (RmiTransaction tx = state.trace.startTx("ghidraTraceInsertObj", false)) {
			Lifespan span = state.trace.proxyObjectPath(path)
					.insert(state.trace.getSnap(), Resolution.CR_ADJUST);
			System.out.println("Inserted object: lifespan=" + span);
		}
	}

	public void ghidraTraceRemoveObj(String path) {
		state.requireTx();
		try (RmiTransaction tx = state.trace.startTx("ghidraTraceRemoveObj", false)) {
			Lifespan span = state.trace.proxyObjectPath(path).remove(state.trace.getSnap(), false);
			System.out.println("Removed object: lifespan=" + span);
		}
	}

	public void ghidraTraceSetValue(String path, String key, Object value) {
		state.requireTx();
		try (RmiTransaction tx = state.trace.startTx("ghidraTraceSetValue", false)) {
			setValue(path, key, value);
		}
	}

	public void ghidraTraceRetainValues(String kind, String path, Set<String> keys) {
		state.requireTx();
		ValueKinds kinds = ValueKinds.VK_ELEMENTS;
		if (kind != null && kind.startsWith("--")) {
			if (kind.equals("--elements")) {
				kinds = ValueKinds.VK_ELEMENTS;
			}
			if (kind.equals("--attributes")) {
				kinds = ValueKinds.VK_ATTRIBUTES;
			}
			if (kind.equals("--both")) {
				kinds = ValueKinds.VK_BOTH;
			}
		}
		state.trace.proxyObjectPath(path).retainValues(keys, state.trace.getSnap(), kinds);
	}

	public RmiTraceObject ghidraTraceGetObj(String path) {
		state.requireTrace();
		return state.trace.proxyObjectPath(path);
	}

	public static class Tabulator {
		static class Column {
			int width;

			public void measure(String string) {
				width = Math.max(width, string.length());
			}

			public void print(PrintStream out, String string) {
				out.print(pad(string));
			}

			private String pad(String string) {
				return StringUtils.rightPad(string, width);
			}
		}

		private final PrintStream out;
		private final List<Column> columns;

		public Tabulator(PrintStream out, int colCount) {
			this.out = out;
			this.columns = IntStream.range(0, colCount).mapToObj(i -> new Column()).toList();
		}

		public void measure(Object... row) {
			if (row.length != columns.size()) {
				throw new IllegalArgumentException("Column count mismatch");
			}
			for (int i = 0; i < row.length; i++) {
				columns.get(i).measure(row[i].toString());
			}
		}

		public void print(Object... row) {
			if (row.length != columns.size()) {
				throw new IllegalArgumentException("Column count mismatch");
			}
			for (int i = 0; i < row.length; i++) {
				if (i != 0) {
					out.print(" ");
				}
				columns.get(i).print(out, row[i].toString());
			}
			out.println();
		}
	}

	public void printValues(List<RmiTraceObjectValue> values) {
		Tabulator tab = new Tabulator(System.out, 5);
		tab.measure("Parent", "Key", "Span", "Value", "Type");
		for (RmiTraceObjectValue d : values) {
			tab.measure(d.parent().getPath(), d.span(), d.key(), d.value(), d.schema());
		}
		tab.print("Parent", "Key", "Span", "Value", "Type");
		for (RmiTraceObjectValue d : values) {
			tab.print(d.parent().getPath(), d.span(), d.key(), d.value(), d.schema());
		}
	}

	public void ghidraTraceGetValues(String pattern) {
		state.requireTrace();
		List<RmiTraceObjectValue> values = state.trace.getValues(pattern);
		printValues(values);
	}

	public void ghidraTraceGetValuesRng(Address addr, long sz) {
		state.requireTrace();
		List<RmiTraceObjectValue> values = state.trace.getValuesRng(addr, sz);
		printValues(values);
	}

	public void ghidraTracePutVMs() {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutVMs", false)) {
			putVMs();
		}
	}

	public void ghidraTracePutProcesses() {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutVMs", false)) {
			putProcesses();
		}
	}

	public void ghidraTracePutBreakpoints() {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutBreakpoints", false)) {
			putBreakpoints();
		}
	}

	public void ghidraTracePutEvents() {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutEvents", false)) {
			putEvents();
		}
	}

	public void activate(String path) {
		state.requireTrace();
		if (path == null) {
			VirtualMachine currentVM = connector.getJdi().getCurrentVM();
			path = getPath(currentVM);
			try {
				ThreadReference currentThread = connector.getJdi().getCurrentThread();
				if (currentThread != null) {
					path = getPath(currentThread);
				}
				StackFrame currentFrame = connector.getJdi().getCurrentFrame();
				if (currentFrame != null) {
					path = getPath(currentFrame);
				}
			}
			catch (VMDisconnectedException discExc) {
				Msg.info(this, "Activate failed - VM disconnected");
			}
		}
		state.trace.activate(path);
	}

	public void ghidraTraceActivate(String path) {
		activate(path);
	}

	public void ghidraTraceDisassemble(Address address) {
		state.requireTrace();
		MemoryMapper mapper = state.trace.memoryMapper;
		Address mappedAddress = mapper.map(address);
		AddressSpace addressSpace = mappedAddress.getAddressSpace();
		if (!addressSpace.equals(address.getAddressSpace())) {
			state.trace.createOverlaySpace(mappedAddress, address);
		}
		state.trace.disassemble(mappedAddress, state.trace.getSnap());
	}

	// STATE //

	public void putMemState(Address start, long length, MemoryState memState, boolean usePages) {
		Address mapped = state.trace.memoryMapper.map(start);
		if (mapped.getAddressSpace() != start.getAddressSpace() &&
			!memState.equals(MemoryState.MS_UNKNOWN)) {
			state.trace.createOverlaySpace(mapped, start);
		}
		AddressRangeImpl range = new AddressRangeImpl(mapped, mapped.add(length - 1));
		state.trace.setMemoryState(range, memState, state.trace.getSnap());
	}

	public void putReg(StackFrame frame) {
		String ppath = getPath(frame);
		if (ppath == null) {
			Msg.error(this, "Null path for " + frame);
			return;
		}
		String path = ppath + ".Registers";
		state.trace.createOverlaySpace("register", path);
		RegisterValue[] rvs = putRegisters(frame, path);
		state.trace.putRegisters(path, rvs, state.trace.getSnap());
	}

	public RegisterValue[] putRegisters(StackFrame frame, String ppath) {
		JdiArch arch = connector.getArch();
		Language lang = arch.getLanguage();
		Set<String> keys = new HashSet<>();
		RegisterValue[] rvs = new RegisterValue[regNames.length];

		int ireg = 0;
		String r = regNames[0];
		Register register = lang.getRegister(r);
		if (register == null) {
			register = fabricatePcRegister(lang, r);
		}
		keys.add(connector.key(r));
		Location loc = frame.location();
		Address addr = putRegister(ppath, r, loc);
		RegisterValue rv = new RegisterValue(register, BigInteger.valueOf(addr.getOffset()));
		rvs[ireg++] = rv;

		r = regNames[1];
		register = lang.getRegister(r);
		if (register == null) {
			register = fabricatePcRegister(lang, r);
		}
		keys.add(connector.key(r));
		ThreadReference thread = frame.thread();
		Location ploc = null;
		int frameCount;
		try {
			frameCount = thread.frameCount();
			for (int i = 0; i < frameCount; i++) {
				StackFrame f = thread.frame(i);
				if (f.equals(frame) && i < frameCount - 1) {
					ploc = thread.frame(i + 1).location();
				}
			}
		}
		catch (IncompatibleThreadStateException e) {
			// IGNORE
		}
		if (ploc != null) {
			addr = putRegister(ppath, r, ploc);
			rv = new RegisterValue(register, BigInteger.valueOf(addr.getOffset()));
			rvs[ireg++] = rv;
		}
		else {
			rv = new RegisterValue(register, BigInteger.valueOf(0L));
			rvs[ireg++] = rv;
		}

		retainKeys(ppath, keys);
		return rvs;
	}

	public void putCurrentLocation() {
		Location loc = connector.getJdi().getCurrentLocation();
		if (loc == null) {
			return;
		}
		Method m = loc.method();
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		if (connector.getAddressRange(m.declaringType()) == null) {
			putReferenceType(getPath(vm) + ".Classes", m.declaringType(), true);
		}
		else {
			updateMemoryForMethod(m);
		}
	}

	public Address putRegister(String ppath, String name, Location loc) {
		Address addr = connector.getAddressFromLocation(loc);
		RegisterMapper mapper = state.trace.registerMapper;
		String regName = mapper.mapName(name);
		JdiArch arch = connector.getArch();
		Language lang = arch.getLanguage();
		Register register = lang.getRegister(name);
		if (register == null) {
			register = fabricatePcRegister(lang, name);
		}
		RegisterValue rv = new RegisterValue(register, addr.getOffsetAsBigInteger());
		RegisterValue mapped = mapper.mapValue(name, rv);
		Address regAddr = addr.getNewAddress(mapped.getUnsignedValue().longValue());
		setValue(ppath, connector.key(regName), Long.toHexString(regAddr.getOffset()));

		int codeIndex = (int) loc.codeIndex();
		regAddr = regAddr.subtract(codeIndex);
		putMem(regAddr, codeIndex + 1, false);

		return addr;
	}

	private Register fabricatePcRegister(Language lang, String name) {
		int size = lang.getAddressFactory().getDefaultAddressSpace().getSize();
		return new Register(name, name, null, size, lang.isBigEndian(), Register.TYPE_PC);
	}

	public void putMem(Address address, long length, boolean create) {
		MemoryMapper mapper = state.trace.memoryMapper;
		Address mappedAddress = mapper.map(address);
		AddressSpace addressSpace = mappedAddress.getAddressSpace();
		if (!addressSpace.equals(address.getAddressSpace())) {
			state.trace.createOverlaySpace(mappedAddress, address);
		}
		int ilen = (int) length;
		// NB: Right now, we return a full page even if the method/reftype
		//   is missing.  Probably should do something saner, e.g. mark it as an error,
		//   but gets tricky given all the possible callers.
		byte[] bytes = new byte[ilen];
		Arrays.fill(bytes, (byte) 0xFF);
		if (addressSpace.getName().equals("ram")) {
			Method method = connector.getMethodForAddress(address);
			if (method != null) {
				byte[] bytecodes = method.bytecodes();
				if (bytecodes != null) {
					bytes = Arrays.copyOf(bytecodes, ilen);
				}
				state.trace.putBytes(mappedAddress, bytes, state.trace.getSnap());
			}
			else {
				if (create) {
					throw new RuntimeException("Attempt to create existing memory");
				}
			}
			return;
		}
		if (addressSpace.getName().equals("constantPool")) {
			ReferenceType reftype = connector.getReferenceTypeForPoolAddress(address);
			if (reftype != null) {
				byte[] bytecodes = reftype.constantPool();
				if (bytecodes != null) {
					bytes = Arrays.copyOf(bytecodes, ilen);
				}
				state.trace.putBytes(mappedAddress, bytes, state.trace.getSnap());
			}
			return;
		}
		throw new RuntimeException();
	}

	// TYPES //

	public void putType(String ppath, String key, Type type) {
		String path = createObject(type, key, ppath);
		putTypeDetails(path, type);
		insertObject(path);
	}

	public void putTypeDetails(String path, Type type) {
		setValue(path, ATTR_DISPLAY, "Type: " + type.name());
		setValue(path, ATTR_SIGNATURE, type.signature());
	}

	public void putReferenceTypeContainer(String ppath, List<ReferenceType> reftypes) {
		Set<String> keys = new HashSet<>();
		for (ReferenceType ref : reftypes) {
			keys.add(connector.key(ref.name()));
			putReferenceType(ppath, ref, false);
		}
		retainKeys(ppath, keys);
	}

	public void putReferenceType(String ppath, ReferenceType reftype, boolean load) {
		String path = createObject(reftype, reftype.name(), ppath);
		if (connector.getAddressRange(reftype) == null) {
			connector.bumpRamIndex();
		}
		if (load) {
			registerMemory(path, reftype);
		}
		putReferenceTypeDetails(path, reftype);
		insertObject(path);
	}

	public void putReferenceTypeDetails(String path, ReferenceType reftype) {
		String name = reftype.name();
		if (name.indexOf(".") > 0) {
			name = name.substring(name.lastIndexOf(".") + 1);
		}
		setValue(path, ATTR_MODULE_NAME, name + ".class");
		putRefTypeAttributes(path, reftype);
		String fpath = createObject(path + ".Fields");
		String ipath = createObject(path + ".Instances");
		String lpath = createObject(path + ".Locations");
		insertObject(fpath);
		insertObject(ipath);
		insertObject(lpath);
		putMethodContainer(path + ".Methods", reftype);

		String rpath = createObject(path + ".Relations");
		insertObject(rpath);
		try {
			ModuleReference module = reftype.module();
			String moduleName = module.name();
			if (moduleName == null) {
				moduleName = "<unnamed>";
			}
			if (moduleName.contains(".")) {
				moduleName = "\"" + moduleName + "\"";
			}
			String mrpath = createObject(module, moduleName, rpath + ".ModuleRef");
			insertObject(mrpath);
		}
		catch (UnsupportedOperationException e) {
			//Msg.info(this, e.getMessage());
		}

		if (reftype instanceof ArrayType at) {
			putArrayTypeDetails(rpath, at);
		}
		if (reftype instanceof ClassType ct) {
			putClassTypeDetails(rpath, ct);
		}
		if (reftype instanceof InterfaceType it) {
			putInterfaceTypeDetails(rpath, it);
		}
	}

	private void putRefTypeAttributes(String ppath, ReferenceType reftype) {
		String path = createObject(ppath + ".Attributes");
		if (reftype instanceof ArrayType) {
			return;
		}
		try {
			setValue(path, "isAbstract", reftype.isAbstract());
			setValue(path, "isFinal", reftype.isFinal());
			setValue(path, "isInitialized", reftype.isInitialized());
			setValue(path, "isPackagePrivate", reftype.isPackagePrivate());
			setValue(path, "isPrepared", reftype.isPrepared());
			setValue(path, "isPrivate", reftype.isPrivate());
			setValue(path, "isProtected", reftype.isProtected());
			setValue(path, "isPublic", reftype.isPublic());
			setValue(path, "isStatic", reftype.isStatic());
			setValue(path, "isVerified", reftype.isVerified());
		}
		catch (Exception e) {
			if (e instanceof ClassNotLoadedException) {
				setValue(path, "status", "Class not loaded");
			}
		}
		setValue(path, "defaultStratum", reftype.defaultStratum());
		setValue(path, "availableStata", reftype.availableStrata());
		setValue(path, "failedToInitialize", reftype.failedToInitialize());
		insertObject(path);
	}

	private void registerMemory(String path, ReferenceType reftype) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		String mempath = getPath(vm) + ".Memory";
		AddressSet bounds = new AddressSet();
		for (Method m : reftype.methods()) {
			if (m.location() != null) {
				AddressRange range = connector.registerAddressesForMethod(m);
				if (range != null && range.getMinAddress().getOffset() != 0) {
					putMem(range.getMinAddress(), range.getLength(), true);
					bounds.add(range);

					String mpath = createObject(mempath + connector.key(m.toString()));
					setValue(mpath, ATTR_RANGE, range);
					insertObject(mpath);
				}
			}
		}
		AddressRange range = connector.putAddressRange(reftype, bounds);
		setValue(path, ATTR_RANGE, range);

		try {
			setValue(path, ATTR_COUNT, reftype.constantPoolCount());
			range = connector.getPoolAddressRange(reftype, getSize(reftype) - 1);
			setValue(path, ATTR_RANGE_CP, range);
		}
		catch (UnsupportedOperationException e) {
			// Ignore
		}
		try {
			putMem(range.getMinAddress(), range.getLength(), true);
		}
		catch (RuntimeException e) {
			// Ignore
		}
	}

	private void updateMemoryForMethod(Method m) {
		if (m.location() != null) {
			AddressRange range = connector.registerAddressesForMethod(m);
			if (range != null && range.getMinAddress().getOffset() != 0) {
				putMem(range.getMinAddress(), range.getLength(), true);
			}
		}
	}

	public boolean loadReferenceType(String ppath, List<ReferenceType> reftypes,
			String targetClass) {
		boolean result = false;
		List<ReferenceType> classes = reftypes;
		for (ReferenceType ref : classes) {
			if (ref.name().contains(targetClass)) {
				putReferenceType(ppath, ref, true);
				result = true;
			}
		}
		return result;
	}

	public void putArrayTypeDetails(String path, ArrayType type) {
		String cpath = createObject(path + ".ComponentType");
		setValue(path, "ComponentSignature", type.componentSignature());
		setValue(path, "ComponentTypeName", type.componentTypeName());
		insertObject(cpath);
	}

	public void putClassTypes(String ppath, List<ClassType> reftypes) {
		Set<String> keys = new HashSet<>();
		for (ClassType ref : reftypes) {
			keys.add(connector.key(ref.name()));
			putReferenceType(ppath, ref, true);
		}
		retainKeys(ppath, keys);
	}

	public void putClassTypeDetails(String path, ClassType type) {
		setValue(path, "IsEnum", type.isEnum());
		String aipath = createObject(path + ".AllInterfaces");
		String ipath = createObject(path + ".Interfaces");
		String scpath = createObject(path + ".SubClasses");
		String cpath = createObject(path + ".ClassType");
		insertObject(aipath);
		insertObject(ipath);
		insertObject(scpath);
		insertObject(cpath);
	}

	public void putInterfaceTypes(String ppath, List<InterfaceType> reftypes) {
		Set<String> keys = new HashSet<>();
		for (ReferenceType ref : reftypes) {
			keys.add(connector.key(ref.name()));
			putReferenceType(ppath, ref, true);
		}
		retainKeys(ppath, keys);
	}

	public void putInterfaceTypeDetails(String path, InterfaceType type) {
		String impath = createObject(path + ".Implementors");
		String sbpath = createObject(path + ".SubInterfaces");
		String sppath = createObject(path + ".SuperInterfaces");
		insertObject(impath);
		insertObject(sbpath);
		insertObject(sppath);
	}

	// VALUES //

	public void putValueContainer(String path, List<Value> values) {
		for (Value v : values) {
			putValue(path, v.toString(), v);
		}
	}

	public void putValue(String ppath, String key, Value value) {
		String path = createObject(value, key, ppath);
		setValue(path, ATTR_DISPLAY, "Value: " + value.toString());
		//putValueDetailsByType(path, value);
		insertObject(path);
	}

	public void putValueDetailsByType(String path, Value value) {
		if (value instanceof PrimitiveValue pval) {
			putPrimitiveValue(path, pval);
		}
		else if (value instanceof ArrayReference aref) {
			putArrayReferenceDetails(path, aref);
		}
		else if (value instanceof ClassLoaderReference aref) {
			putClassLoaderReferenceDetails(path, aref);
		}
		else if (value instanceof ClassObjectReference aref) {
			putClassObjectReferenceDetails(path, aref);
		}
		else if (value instanceof ModuleReference aref) {
			putModuleReferenceDetails(path, aref);
		}
		else if (value instanceof StringReference aref) {
			putStringReferenceDetails(path, aref);
		}
		else if (value instanceof ThreadGroupReference aref) {
			putThreadGroupReferenceDetails(path, aref);
		}
		else if (value instanceof ThreadReference aref) {
			putThreadReferenceDetails(path, aref);
		}
		else if (value instanceof ObjectReference oref) {
			putObjectReferenceDetails(path, oref);
		}
	}

	public void putValueDetails(String path, Value value) {
		putType(path, ATTR_TYPE, value.type());
	}

	public void putPrimitiveValue(String ppath, PrimitiveValue value) {
		String path = createObject(value, value.toString(), ppath);
		putValueDetails(path, value);
		if (value instanceof BooleanValue v) {
			setValue(path, ATTR_VALUE, v.booleanValue());
		}
		if (value instanceof ByteValue b) {
			setValue(path, ATTR_VALUE, b.byteValue());
		}
		if (value instanceof CharValue v) {
			setValue(path, ATTR_VALUE, v.charValue());
		}
		if (value instanceof ShortValue v) {
			setValue(path, ATTR_VALUE, v.shortValue());
		}
		if (value instanceof IntegerValue v) {
			setValue(path, ATTR_VALUE, v.intValue());
		}
		if (value instanceof LongValue v) {
			setValue(path, ATTR_VALUE, v.longValue());
		}
		if (value instanceof FloatValue v) {
			setValue(path, ATTR_VALUE, v.floatValue());
		}
		if (value instanceof DoubleValue v) {
			setValue(path, ATTR_VALUE, v.doubleValue());
		}
		insertObject(path);
	}

	private Value getPrimitiveValue(Value value, String newVal) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		if (value instanceof BooleanValue) {
			return vm.mirrorOf(Boolean.valueOf(newVal));
		}
		if (value instanceof ByteValue) {
			return vm.mirrorOf(Byte.valueOf(newVal));
		}
		if (value instanceof CharValue) {
			return vm.mirrorOf(newVal.charAt(0));
		}
		if (value instanceof ShortValue) {
			return vm.mirrorOf(Short.valueOf(newVal));
		}
		if (value instanceof IntegerValue) {
			return vm.mirrorOf(Integer.valueOf(newVal));
		}
		if (value instanceof LongValue) {
			return vm.mirrorOf(Long.valueOf(newVal));
		}
		if (value instanceof FloatValue) {
			return vm.mirrorOf(Float.valueOf(newVal));
		}
		if (value instanceof DoubleValue) {
			return vm.mirrorOf(Double.valueOf(newVal));
		}
		if (value instanceof StringReference) {
			return vm.mirrorOf(newVal);
		}
		return null;
	}

	public void modifyValue(LocalVariable lvar, String valstr) {
		String path = getPath(lvar);
		String ppath = getParentPath(path);
		Object parent = connector.objForPath(ppath);
		if (parent instanceof StackFrame frame) {
			Value orig = frame.getValue(lvar);
			Value repl = getPrimitiveValue(orig, valstr);
			if (repl != null) {
				try {
					frame.setValue(lvar, repl);
				}
				catch (InvalidTypeException e) {
					Msg.error(this, "Invalid type for " + lvar);
				}
				catch (ClassNotLoadedException e) {
					Msg.error(this, "Class not loaded for " + lvar);
				}

				putLocalVariable(ppath + ".Variables", lvar, repl);
			}
		}
		Msg.error(this, "Cannot set value for " + lvar);
	}

	public void modifyValue(Field field, String valstr) {
		String path = getPath(field);
		String ppath = getParentPath(path);
		Object parent = connector.objForPath(ppath);
		if (parent instanceof ObjectReference ref) {
			Value orig = ref.getValue(field);
			Value repl = getPrimitiveValue(orig, valstr);
			if (repl != null) {
				try {
					ref.setValue(field, repl);
				}
				catch (InvalidTypeException e) {
					Msg.error(this, "Invalid type for " + field);
				}
				catch (ClassNotLoadedException e) {
					Msg.error(this, "Class not loaded for " + field);
				}
				putField(ppath + ".Variables", field, repl);
			}
		}
		Msg.error(this, "Cannot set value for " + field);
	}

	public void putObjectContainer(String path, List<ObjectReference> objects) {
		for (ObjectReference obj : objects) {
			String opath = createObject(obj, obj.toString(), path);
			insertObject(opath);
		}
	}

	public void putObjectReference(String ppath, ObjectReference ref) {
		String path = createObject(ref, ref.toString(), ppath);
		putObjectReferenceDetails(path, ref);
		insertObject(path);
	}

	public void putObjectReferenceDetails(String path, ObjectReference ref) {
		putValueDetails(path, ref);
		setValue(path, "UniqueId", ref.uniqueID());
		String apath = createObject(path + ".Attributes");
		try {
			setValue(apath, "entryCount", ref.entryCount());
		}
		catch (IncompatibleThreadStateException e) {
			// IGNORE
		}
		setValue(apath, "isCollected", ref.isCollected());
		insertObject(apath);
		String rpath = createObject(path + ".Relations");
		try {
			if (ref.owningThread() != null) {
				String otpath = createObject(rpath + ".OwningThread");
				insertObject(otpath);
			}
			if (ref.waitingThreads() != null) {
				String wtpath = createObject(rpath + ".WaitingThreads");
				insertObject(wtpath);
			}
		}
		catch (IncompatibleThreadStateException e) {
			// IGNORE
		}
		if (ref.referenceType() != null) {
			String rtpath = createObject(rpath + ".ReferenceType");
			insertObject(rtpath);
		}
		if (ref.referringObjects(MAX_REFS) != null) {
			String ropath = createObject(rpath + ".ReferringObjects");
			insertObject(ropath);
		}
		if (!(ref instanceof ArrayReference)) {
			String vpath = createObject(path + ".Variables");
			insertObject(vpath);
		}
		insertObject(rpath);
	}

	public void putArrayReference(String ppath, ArrayReference ref) {
		String path = createObject(ref, ref.toString(), ppath);
		putArrayReferenceDetails(path, ref);
		insertObject(path);
	}

	public void putArrayReferenceDetails(String path, ArrayReference ref) {
		putObjectReferenceDetails(path, ref);
		setValue(path, ATTR_LENGTH, ref.length());
		String vpath = createObject(path + ".Values");
		insertObject(vpath);
	}

	public void putClassLoaderReference(String ppath, ClassLoaderReference ref) {
		String path = createObject(ref, ref.toString(), ppath);
		putClassLoaderReferenceDetails(path, ref);
		insertObject(path);
	}

	public void putClassLoaderReferenceDetails(String path, ClassLoaderReference ref) {
		putObjectReferenceDetails(path, ref);
		String dcpath = createObject(path + ".DefinedClasses");
		String vcpath = createObject(path + ".VisibleClasses");
		insertObject(dcpath);
		insertObject(vcpath);
	}

	public void putClassObjectReference(String ppath, ClassObjectReference ref) {
		String path = createObject(ref, ref.toString(), ppath);
		putClassObjectReferenceDetails(path, ref);
		insertObject(path);
	}

	public void putClassObjectReferenceDetails(String path, ClassObjectReference ref) {
		putObjectReferenceDetails(path, ref);
		String rtpath = createObject(path + ".ReflectedType");
		insertObject(rtpath);
	}

	public void putModuleReferenceContainer() {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		String ppath = getPath(vm) + ".ModuleRefs";
		Set<String> keys = new HashSet<>();
		try {
			List<ModuleReference> modules = vm.allModules();
			for (ModuleReference ref : modules) {
				keys.add(connector.key(ref.name()));
				String mpath = createObject(ref, ref.name(), ppath);
				insertObject(mpath);
			}
		}
		catch (UnsupportedOperationException e) {
			// Msg.info(this,  e.getMessage());
		}
		retainKeys(ppath, keys);
	}

	public void putModuleReference(String ppath, ModuleReference ref) {
		String path = createObject(ref, ref.name(), ppath);
		putModuleReferenceDetails(path, ref);
		insertObject(path);
	}

	public void putModuleReferenceDetails(String path, ModuleReference ref) {
		putObjectReferenceDetails(path, ref);
		String clpath = createObject(path + ".ClassLoader");
		insertObject(clpath);
	}

	public void putStringReference(String ppath, StringReference ref) {
		String path = createObject(ref, ref.toString(), ppath);
		putStringReferenceDetails(path, ref);
		insertObject(path);
	}

	public void putStringReferenceDetails(String path, StringReference ref) {
		putObjectReferenceDetails(path, ref);
		setValue(path, ATTR_VALUE, ref.value());
	}

	public void putThreadGroupContainer(String refpath, List<ThreadGroupReference> refs) {
		String ppath = refpath + ".ThreadGroups";
		Set<String> keys = new HashSet<>();
		for (ThreadGroupReference subref : refs) {
			keys.add(connector.key(subref.name()));
			putThreadGroupReference(ppath, subref);
		}
		retainKeys(ppath, keys);
	}

	public void putThreadGroupReference(String ppath, ThreadGroupReference ref) {
		String path = createObject(ref, ref.name(), ppath);
		putThreadGroupReferenceDetails(path, ref);
		insertObject(path);
	}

	public void putThreadGroupReferenceDetails(String path, ThreadGroupReference ref) {
		putObjectReferenceDetails(path, ref);
		if (ref.parent() != null) {
			String ppath = createObject(path + ".Parent");
			insertObject(ppath);
		}
		String tgpath = createObject(path + ".ThreadGroups");
		String tpath = createObject(path + ".Threads");
		insertObject(tgpath);
		insertObject(tpath);
	}

	public void putThreadContainer(String refpath, List<ThreadReference> refs, boolean asLink) {
		String ppath = refpath + ".Threads";
		Set<String> keys = new HashSet<>();
		for (ThreadReference subref : refs) {
			keys.add(connector.key(subref.name()));
			if (asLink) {
				createLink(ppath, subref.name(), subref);
			}
			else {
				putThreadReference(ppath, subref);
			}
		}
		retainKeys(ppath, keys);
	}

	public void putThreadReference(String ppath, ThreadReference ref) {
		String path = createObject(ref, ref.name(), ppath);
		putThreadReferenceDetails(path, ref);
		insertObject(path);
	}

	public void putThreadReferenceDetails(String path, ThreadReference ref) {
		putObjectReferenceDetails(path, ref);
		String spath = createObject(path + ".Stack");
		String rpath = createObject(path + ".Relations");
		String ccpath = createObject(rpath + ".CurrentContendedMonitor");
		String ompath = createObject(rpath + ".OwnedMonitors");
		String omfpath = createObject(rpath + ".OwnedMonitorsAndFrames");
		String tgpath = createObject(rpath + ".ThreadGroup");
		putThreadAttributes(ref, path);
		insertObject(spath);
		insertObject(ccpath);
		insertObject(ompath);
		insertObject(omfpath);
		insertObject(tgpath);
	}

	void putThreadAttributes(ThreadReference thread, String ppath) {
		String path = createObject(ppath + ".Attributes");
		setValue(path, "Status", thread.status());
		setValue(path, "isAtBreakpoint", thread.isAtBreakpoint());
		setValue(path, "isCollected", thread.isCollected());
		setValue(path, "isSuspended", thread.isSuspended());
		setValue(path, "isVirtual", thread.isVirtual());
		try {
			setValue(path, "entryCount", thread.entryCount());
		}
		catch (IncompatibleThreadStateException e) {
			// Ignore
		}
		try {
			setValue(path, "frameCount", thread.frameCount());
		}
		catch (IncompatibleThreadStateException e) {
			// Ignore
		}
		setValue(path, "suspendCount", thread.suspendCount());
		insertObject(path);
	}

	public void putMonitorInfoContainer(String path, List<MonitorInfo> info) {
		for (MonitorInfo f : info) {
			String ipath = createObject(f, f.toString(), path);
			insertObject(ipath);
		}
	}

	public void putMonitorInfoDetails(String path, MonitorInfo info) {
		setValue(path, "StackDepth", info.stackDepth());
		String mpath = createObject(path + ".Monitor");
		String tpath = createObject(path + ".Thread");
		insertObject(mpath);
		insertObject(tpath);
	}

	// TYPE COMPONENTS

	public void putFieldContainer(String path, ReferenceType reftype) {
		boolean scope = connector.getScope(reftype);
		List<Field> fields = scope ? reftype.allFields() : reftype.fields();
		Set<String> keys = new HashSet<>();
		for (Field f : fields) {
			Value value = null;
			try {
				value = reftype.getValue(f);
				if (value != null) {
					keys.add(connector.key(value.toString()));
				}
			}
			catch (IllegalArgumentException iae) {
				// IGNORE
			}
			keys.add(connector.key(f.name()));
			putField(path, f, value);
		}
		retainKeys(path, keys);
	}

	public void putVariableContainer(String path, ObjectReference ref) {
		boolean scope = connector.getScope(ref);
		List<Field> fields = scope ? ref.referenceType().allFields() : ref.referenceType().fields();
		Set<String> keys = new HashSet<>();
		for (Field f : fields) {
			Value value = null;
			try {
				value = ref.getValue(f);
				keys.add(connector.key(value.toString()));
			}
			catch (IllegalArgumentException iae) {
				// IGNORE
			}
			keys.add(connector.key(f.name()));
			putField(path, f, value);
		}
		retainKeys(path, keys);
	}

	public void putField(String ppath, Field f, Value value) {
		String path = createObject(f, f.name(), ppath);
		putFieldDetails(path, f);
		if (value != null) {
			putValue(path, ATTR_VALUE, value);
			setValue(path, ATTR_DISPLAY, f.name() + " (" + f.typeName() + ") : " + value);
		}
		else {
			setValue(path, ATTR_DISPLAY, f.name() + " (" + f.typeName() + ")");
		}
		insertObject(path);
	}

	public void putFieldDetails(String path, Field f) {
		setValue(path, ATTR_MODULE_NAME, f.declaringType().name());
		if (f.genericSignature() != null) {
			setValue(path, "GenericSignature", f.genericSignature());
		}
		putFieldAttributes(path, f);
		try {
			putType(path, ATTR_TYPE, f.type());
		}
		catch (ClassNotLoadedException e) {
			// IGNORE
		}
	}

	private void putFieldAttributes(String ppath, Field f) {
		String path = createObject(ppath + ".Attributes");
		setValue(path, "Modifiers", Integer.toHexString(f.modifiers()));
		setValue(path, "Signature", f.signature());
		setValue(path, "isEnumConstant", f.isEnumConstant());
		setValue(path, "isFinal", f.isFinal());
		setValue(path, "isPackagePrivate", f.isPackagePrivate());
		setValue(path, "isPrivate", f.isPrivate());
		setValue(path, "isProtected", f.isProtected());
		setValue(path, "isPublic", f.isPublic());
		setValue(path, "isStatic", f.isStatic());
		setValue(path, "isSynthetic", f.isSynthetic());
		setValue(path, "isTransient", f.isTransient());
		setValue(path, "isVolatile", f.isVolatile());
		insertObject(path);
	}

	public void putMethodContainer(String path, ReferenceType reftype) {
		boolean scope = connector.getScope(reftype);
		Set<String> keys = new HashSet<>();
		try {
			List<Method> methods = scope ? reftype.allMethods() : reftype.methods();
			for (Method m : methods) {
				keys.add(connector.key(m.name()));
				putMethod(path, m);
			}
		}
		catch (Exception e) {
			Msg.info(this, e.getMessage());
		}
		retainKeys(path, keys);
	}

	public void putMethod(String ppath, Method m) {
		String path = createObject(m, m.name(), ppath);
		putMethodDetails(path, m, true);
		insertObject(path);
	}

	public void putMethodDetails(String path, Method m, boolean partial) {
		ReferenceType declaringType = m.declaringType();
		setValue(path, ATTR_MODULE_NAME, declaringType.name());
		createLink(m, "DeclaringType", declaringType);
		if (!partial) {
			String apath = createObject(path + ".Arguments");
			if (m.genericSignature() != null) {
				setValue(path, "GenericSignature", m.genericSignature());
			}
			String lpath = createObject(path + ".Locations");
			setValue(path, "Modifiers", m.modifiers());
			setValue(path, "ReturnType", m.returnTypeName());
			setValue(path, "Signature", m.signature());
			String vpath = createObject(path + ".Variables");
			putMethodAttributes(path, m);
			insertObject(apath);
			insertObject(lpath);
			insertObject(vpath);
		}
		if (m.location() != null) {
			AddressRange range = connector.getAddressRange(m);
			if (!range.equals(connector.defaultRange)) {
				setValue(path, ATTR_RANGE, range);
			}
		}
		String bytes = "";
		for (byte b : m.bytecodes()) {
			bytes += Integer.toHexString(b & 0xff);
		}
		setValue(path, "ByteCodes", bytes);
	}

	private void putMethodAttributes(String ppath, Method m) {
		String path = createObject(ppath + ".Attributes");
		setValue(path, "isAbstract", m.isAbstract());
		setValue(path, "isBridge", m.isBridge());
		setValue(path, "isConstructor", m.isConstructor());
		setValue(path, "isDefault", m.isDefault());
		setValue(path, "isFinal", m.isFinal());
		setValue(path, "isNative", m.isNative());
		setValue(path, "isObsolete", m.isObsolete());
		setValue(path, "isPackagePrivate", m.isPackagePrivate());
		setValue(path, "isPrivate", m.isPrivate());
		setValue(path, "isProtected", m.isProtected());
		setValue(path, "isPublic", m.isPublic());
		setValue(path, "isStatic", m.isStatic());
		setValue(path, "isStaticInitializer", m.isStaticInitializer());
		setValue(path, "isSynchronized", m.isSynchronized());
		setValue(path, "isSynthetic", m.isSynthetic());
		setValue(path, "isVarArgs", m.isVarArgs());
		insertObject(path);
	}

	// OTHER OBJECTS //

	public void putVMs() {
		try {
			Set<String> keys = new HashSet<>();
			for (Entry<String, VirtualMachine> entry : jdi.listVMs().get().entrySet()) {
				VirtualMachine vm = entry.getValue();
				keys.add(connector.key(vm.name()));
				putVM("VMs", vm);
			}
			retainKeys("VMs", keys);
		}
		catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
	}

	public void putVM(String ppath, VirtualMachine vm) {
		String path = createObject(vm, vm.name(), ppath);
		putVMDetails(path, vm);
		insertObject(path);
	}

	public void putVMDetails(String path, VirtualMachine vm) {
		String cpath = createObject(path + ".Classes");
		String mpath = createObject(path + ".Memory");
		String tgpath = createObject(path + ".ThreadGroups");
		String tpath = createObject(path + ".Threads");
		Event currentEvent = jdi.getCurrentEvent();
		String shortName = vm.name();
		if (shortName.contains(" ")) {
			shortName = vm.name().substring(0, vm.name().indexOf(" "));
		}
		String display = currentEvent == null ? shortName : shortName + " [" + currentEvent + "]";
		setValue(path, ATTR_DISPLAY, display);
		setValue(path, ATTR_ARCH, vm.name());
		setValue(path, ATTR_DEBUGGER, vm.description());
		setValue(path, ATTR_OS, vm.version());
		insertObject(cpath);
		insertObject(mpath);
		insertObject(tgpath);
		insertObject(tpath);
	}

	public void putProcesses() {
		Map<String, VirtualMachine> vms;
		try {
			vms = jdi.listVMs().get();
		}
		catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
			return;
		}
		for (Entry<String, VirtualMachine> entry : vms.entrySet()) {
			Set<String> keys = new HashSet<>();
			VirtualMachine vm = entry.getValue();
			String path = getPath(vm);
			if (path != null) {
				String ppath = path + ".Processes";
				Process proc = vm.process();
				if (proc != null) {
					String key = Long.toString(proc.pid());
					keys.add(connector.key(key));
					putProcess(ppath, proc);
				}
				retainKeys(ppath, keys);
			}
		}
	}

	public void putProcess(String ppath, Process proc) {
		String path = createObject(proc, Long.toString(proc.pid()), ppath);
		putProcessDetails(path, proc);
		insertObject(path);
	}

	public void putProcessDetails(String path, Process proc) {
		Info info = proc.info();
		Optional<String> optional = info.command();
		if (optional.isPresent()) {
			setValue(path, ATTR_EXECUTABLE, optional.get());
		}
		optional = info.commandLine();
		if (optional.isPresent()) {
			setValue(path, ATTR_COMMAND_LINE, optional.get());
		}
		setValue(path, ATTR_ALIVE, proc.isAlive());
	}

	public void putFrames() {
		ThreadReference thread = connector.getJdi().getCurrentThread();
		String ppath = createObject(getPath(thread) + ".Stack");
		Set<String> keys = new HashSet<>();
		try {
			int frameCount = thread.frameCount();
			for (int i = 0; i < frameCount; i++) {
				StackFrame frame = thread.frame(i);
				String key = Integer.toString(i);
				keys.add(connector.key(key));
				putFrame(ppath, frame, key);
			}
		}
		catch (IncompatibleThreadStateException e) {
			// IGNORE
		}
		retainKeys(ppath, keys);
		insertObject(ppath);
	}

	private void putFrame(String ppath, StackFrame frame, String key) {
		String path = createObject(frame, key, ppath);
		putFrameDetails(path, frame, key);
		insertObject(path);
	}

	private void putFrameDetails(String path, StackFrame frame, String key) {
		Location location = frame.location();
		setValue(path, ATTR_DISPLAY, "[" + key + "] " + location + ":" + location.method().name() +
			":" + location.codeIndex());
		putLocation(path, ATTR_LOCATION, location);
		Address addr = connector.getAddressFromLocation(location);
		setValue(path, ATTR_PC, addr);

		String rpath = createObject(path + ".Registers");
		putRegisters(frame, rpath);
		insertObject(rpath);
		String vpath = createObject(path + ".Variables");
		insertObject(vpath);
		try {
			String thpath = createObject(frame.thisObject(), "This", path);
			insertObject(thpath);
		}
		catch (Exception e) {
			// Ignore
		}
	}

	public void putLocationContainer(String path, Method m) {
		try {
			for (Location loc : m.allLineLocations()) {
				String lpath = createObject(loc, loc.toString(), path);
				insertObject(lpath);
			}
		}
		catch (AbsentInformationException e) {
			// Ignore
		}
	}

	public void putLocationContainer(String path, ReferenceType ref) {
		try {
			for (Location loc : ref.allLineLocations()) {
				String lpath = createObject(loc, loc.toString(), path);
				insertObject(lpath);
			}
		}
		catch (AbsentInformationException e) {
			// Ignore
		}
	}

	public void putLocation(String ppath, String key, Location location) {
		String path = createObject(location, key, ppath);
		putLocationDetails(path, location);
		insertObject(path);
	}

	public void putLocationDetails(String path, Location location) {
		Address addr = connector.getAddressFromLocation(location);
		if (isLoaded(location)) {
			setValue(path, ATTR_DISPLAY, connector.key(location.toString()) + ": " + addr);
			setValue(path, ATTR_ADDRESS, addr);
		}
		setValue(path, ATTR_INDEX, location.codeIndex());
		setValue(path, ATTR_LINENO, location.lineNumber());
		try {
			setValue(path, ATTR_NAME, location.sourceName());
		}
		catch (AbsentInformationException e) {
			// sourceName is not available. IGNORE
		}
		try {
			setValue(path, "Path", location.sourcePath());
		}
		catch (AbsentInformationException e) {
			// sourcePath is not available. IGNORE
		}
		Method method = location.method();
		RmiTraceObject methodObject = proxyObject(method);
		if (methodObject == null) {
			String ppath = getVmPath(method.virtualMachine()) + ".Classes";
			putReferenceType(ppath, method.declaringType(), true);
		}
		createLink(location, "Method", method);
		createLink(location, "DeclaringType", location.declaringType());
		try {
			createLink(location, "ModuleRef", location.declaringType().module());
		}
		catch (UnsupportedOperationException e) {
			// IGNORE
		}
	}

	private boolean isLoaded(Location location) {
		AddressRange range = connector.getAddressRange(location.method());
		return !range.equals(connector.defaultRange);
	}

	public void putLocalVariableContainer(String path, Map<LocalVariable, Value> variables) {
		for (LocalVariable lv : variables.keySet()) {
			putLocalVariable(path, lv, variables.get(lv));
		}
	}

	public void putLocalVariableContainer(String path, List<LocalVariable> variables) {
		for (LocalVariable lv : variables) {
			putLocalVariable(path, lv, null);
		}
	}

	public void putLocalVariable(String ppath, LocalVariable lv, Value value) {
		String path = createObject(lv, lv.name(), ppath);
		putLocalVariableDetails(path, lv);
		if (value != null) {
			putValue(path, ATTR_VALUE, value);
			setValue(path, ATTR_DISPLAY, lv.name() + ": " + value);
		}
		insertObject(path);
	}

	public void putLocalVariableDetails(String path, LocalVariable lv) {
		try {
			putType(path, ATTR_TYPE, lv.type());
		}
		catch (ClassNotLoadedException e) {
			// IGNORE
		}
		putLocalVariableAttributes(path, lv);
	}

	private void putLocalVariableAttributes(String ppath, LocalVariable lv) {
		String path = createObject(ppath + ".Attributes");
		setValue(path, "isArgument", lv.isArgument());
		if (lv.genericSignature() != null) {
			setValue(path, "GenericSignature", lv.genericSignature());
		}
		setValue(path, "Signature", lv.signature());
		insertObject(path);
	}

	public void putMethodTypeContainer(String ppath, Method m) {
		try {
			for (Type type : m.argumentTypes()) {
				String tpath = createObject(type, type.name(), ppath);
				insertObject(tpath);
			}
		}
		catch (ClassNotLoadedException e) {
			String epath = createObject(ppath + "Class Not Loaded");
			insertObject(epath);
		}
	}

	public void putBreakpoints() {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		EventRequestManager requestManager = vm.eventRequestManager();
		String ppath = getPath(vm) + ".Breakpoints";
		String path = createObject(ppath);
		Set<String> keys = new HashSet<>();

		List<BreakpointRequest> brkReqs = requestManager.breakpointRequests();
		for (BreakpointRequest req : brkReqs) {
			String key = connector.key(req.toString());
			keys.add(key);
			putReqBreakpoint(ppath, req, key);
		}

		List<AccessWatchpointRequest> watchReqs = requestManager.accessWatchpointRequests();
		for (AccessWatchpointRequest req : watchReqs) {
			String key = connector.key(req.toString());
			keys.add(key);
			putReqAccessWatchpoint(ppath, req, key);
		}

		List<ModificationWatchpointRequest> modReqs =
			requestManager.modificationWatchpointRequests();
		for (ModificationWatchpointRequest req : modReqs) {
			String key = connector.key(req.toString());
			keys.add(key);
			putReqModificationWatchpoint(ppath, req, key);
		}

		retainKeys(ppath, keys);
		insertObject(path);
	}

	public void putEvents() {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		EventRequestManager requestManager = vm.eventRequestManager();
		String ppath = getPath(vm) + ".Events";
		String path = createObject(ppath);
		Set<String> keys = new HashSet<>();

		List<VMDeathRequest> deathReqs = requestManager.vmDeathRequests();
		for (VMDeathRequest req : deathReqs) {
			keys.add(connector.key(req.toString()));
			putReqVMDeath(ppath, req, req.toString());
		}

		List<ThreadStartRequest> threadStartReqs = requestManager.threadStartRequests();
		for (ThreadStartRequest req : threadStartReqs) {
			keys.add(connector.key(req.toString()));
			putReqThreadStarted(ppath, req, req.toString());
		}

		List<ThreadDeathRequest> threadDeathReqs = requestManager.threadDeathRequests();
		for (ThreadDeathRequest req : threadDeathReqs) {
			keys.add(connector.key(req.toString()));
			putReqThreadExited(ppath, req, req.toString());
		}

		List<ExceptionRequest> excReqs = requestManager.exceptionRequests();
		for (ExceptionRequest req : excReqs) {
			keys.add(connector.key(req.toString()));
			putReqException(ppath, req, req.toString());
		}

		List<ClassPrepareRequest> loadReqs = requestManager.classPrepareRequests();
		for (ClassPrepareRequest req : loadReqs) {
			keys.add(connector.key(req.toString()));
			putReqClassLoad(ppath, req, req.toString());
		}

		List<ClassUnloadRequest> unloadReqs = requestManager.classUnloadRequests();
		for (ClassUnloadRequest req : unloadReqs) {
			keys.add(connector.key(req.toString()));
			putReqClassUnload(ppath, req, req.toString());
		}

		List<MethodEntryRequest> entryReqs = requestManager.methodEntryRequests();
		for (MethodEntryRequest req : entryReqs) {
			keys.add(connector.key(req.toString()));
			putReqMethodEntry(ppath, req, req.toString());
		}

		List<MethodExitRequest> exitReqs = requestManager.methodExitRequests();
		for (MethodExitRequest req : exitReqs) {
			keys.add(connector.key(req.toString()));
			putReqMethodExit(ppath, req, req.toString());
		}

		List<StepRequest> stepReqs = requestManager.stepRequests();
		for (StepRequest req : stepReqs) {
			keys.add(connector.key(req.toString()));
			putReqStep(ppath, req, req.toString());
		}

		List<MonitorContendedEnterRequest> monEnterReqs =
			requestManager.monitorContendedEnterRequests();
		for (MonitorContendedEnterRequest req : monEnterReqs) {
			keys.add(connector.key(req.toString()));
			putReqMonContendedEnter(ppath, req, req.toString());
		}

		List<MonitorContendedEnteredRequest> monEnteredReqs =
			requestManager.monitorContendedEnteredRequests();
		for (MonitorContendedEnteredRequest req : monEnteredReqs) {
			keys.add(connector.key(req.toString()));
			putReqMonContendedEntered(ppath, req, req.toString());
		}

		List<MonitorWaitRequest> monWaitReqs = requestManager.monitorWaitRequests();
		for (MonitorWaitRequest req : monWaitReqs) {
			keys.add(connector.key(req.toString()));
			putReqMonWait(ppath, req, req.toString());
		}

		List<MonitorWaitedRequest> monWaitedReqs = requestManager.monitorWaitedRequests();
		for (MonitorWaitedRequest req : monWaitedReqs) {
			keys.add(connector.key(req.toString()));
			putReqMonWaited(ppath, req, req.toString());
		}

		retainKeys(ppath, keys);
		insertObject(path);
	}

	// REQUESTS //

	private void putReqVMDeath(String ppath, VMDeathRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqVMDeathDetails(path, req, key);
		insertObject(path);
	}

	private void putReqVMDeathDetails(String path, VMDeathRequest req, String key) {
		putFilterDetails(path, req);
	}

	private void putReqThreadStarted(String ppath, ThreadStartRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqThreadStartedDetails(path, req, key);
		insertObject(path);
	}

	private void putReqThreadStartedDetails(String path, ThreadStartRequest req, String key) {
		putFilterDetails(path, req);
	}

	private void putReqThreadExited(String ppath, ThreadDeathRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqThreadExitedDetails(path, req, key);
		insertObject(path);
	}

	private void putReqThreadExitedDetails(String path, ThreadDeathRequest req, String key) {
		putFilterDetails(path, req);
	}

	private void putReqBreakpoint(String ppath, BreakpointRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqBreakpointDetails(path, req, key);
		insertObject(path);
	}

	private void putReqBreakpointDetails(String path, BreakpointRequest req, String key) {
		Location location = req.location();
		setValue(path, ATTR_DISPLAY, "[" + key + "] " + location + ":" + location.method().name() +
			":" + location.codeIndex());
		Address addr = connector.getAddressFromLocation(location);
		AddressRangeImpl range = new AddressRangeImpl(addr, addr);
		setValue(path, ATTR_RANGE, range);
		String lpath = createObject(location, location.toString(), path + ".Location");
		insertObject(lpath);
		setValue(path, ATTR_ENABLED, req.isEnabled());
		putFilterDetails(path, req);
	}

	private void putReqAccessWatchpoint(String ppath, AccessWatchpointRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqAccessWatchpointDetails(path, req, key);
		insertObject(path);
	}

	private void putReqAccessWatchpointDetails(String path, AccessWatchpointRequest req,
			String key) {
		Field field = req.field();
		setValue(path, ATTR_DISPLAY, "[" + key + "] " + field + ":" + field.declaringType());
		// NB: This isn't correct, but we need a range (any range)
		AddressRange range =
			connector.getPoolAddressRange(field.declaringType(), getSize(field.declaringType()));
		setValue(path, ATTR_RANGE, range);
		String fpath = createObject(field, field.toString(), path + ".Field");
		insertObject(fpath);
		setValue(path, ATTR_ENABLED, req.isEnabled());
		putFilterDetails(path, req);
	}

	private void putReqModificationWatchpoint(String ppath, ModificationWatchpointRequest req,
			String key) {
		String path = createObject(req, key, ppath);
		putReqModificationWatchpointDetails(path, req, key);
		insertObject(path);
	}

	private void putReqModificationWatchpointDetails(String path, ModificationWatchpointRequest req,
			String key) {
		Field field = req.field();
		setValue(path, ATTR_DISPLAY, "[" + key + "] " + field + ":" + field.declaringType());
		// NB: This isn't correct, but we need a range (any range)
		AddressRange range =
			connector.getPoolAddressRange(field.declaringType(), getSize(field.declaringType()));
		setValue(path, ATTR_RANGE, range);
		String fpath = createObject(field, field.toString(), path + ".Field");
		insertObject(fpath);
		setValue(path, ATTR_ENABLED, req.isEnabled());
		putFilterDetails(path, req);
	}

	private void putReqException(String ppath, ExceptionRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqExceptionDetails(path, req, key);
		insertObject(path);
	}

	private void putReqExceptionDetails(String path, ExceptionRequest req, String key) {
		setValue(path, ATTR_ENABLED, req.isEnabled());
	}

	private void putReqClassLoad(String ppath, ClassPrepareRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqClassLoadDetails(path, req, key);
		insertObject(path);
	}

	private void putReqClassLoadDetails(String path, ClassPrepareRequest req, String key) {
		setValue(path, ATTR_ENABLED, req.isEnabled());
		putFilterDetails(path, req);
	}

	private void putReqClassUnload(String ppath, ClassUnloadRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqClassUnloadDetails(path, req, key);
		insertObject(path);
	}

	private void putReqClassUnloadDetails(String path, ClassUnloadRequest req, String key) {
		setValue(path, ATTR_ENABLED, req.isEnabled());
		putFilterDetails(path, req);
	}

	private void putReqMethodEntry(String ppath, MethodEntryRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqMethodEntryDetails(path, req, key);
		insertObject(path);
	}

	private void putReqMethodEntryDetails(String path, MethodEntryRequest req, String key) {
		setValue(path, ATTR_ENABLED, req.isEnabled());
		putFilterDetails(path, req);
	}

	private void putReqMethodExit(String ppath, MethodExitRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqMethodExitDetails(path, req, key);
		insertObject(path);
	}

	private void putReqMethodExitDetails(String path, MethodExitRequest req, String key) {
		setValue(path, ATTR_ENABLED, req.isEnabled());
		putFilterDetails(path, req);
	}

	private void putReqStep(String ppath, StepRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqStepRequestDetails(path, req, key);
		insertObject(path);
	}

	private void putReqStepRequestDetails(String path, StepRequest req, String key) {
		setValue(path, ATTR_ENABLED, req.isEnabled());
		putFilterDetails(path, req);
	}

	private void putReqMonContendedEnter(String ppath, MonitorContendedEnterRequest req,
			String key) {
		String path = createObject(req, key, ppath);
		putReqMonContendedEnterDetails(path, req, key);
		insertObject(path);
	}

	private void putReqMonContendedEnterDetails(String path, MonitorContendedEnterRequest req,
			String key) {
		putFilterDetails(path, req);
	}

	private void putReqMonContendedEntered(String ppath, MonitorContendedEnteredRequest req,
			String key) {
		String path = createObject(req, key, ppath);
		putReqMonContendedEnteredDetails(path, req, key);
		insertObject(path);
	}

	private void putReqMonContendedEnteredDetails(String path, MonitorContendedEnteredRequest req,
			String key) {
		putFilterDetails(path, req);
	}

	private void putReqMonWait(String ppath, MonitorWaitRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqMonWaitDetails(path, req, key);
		insertObject(path);
	}

	private void putReqMonWaitDetails(String path, MonitorWaitRequest req, String key) {
		putFilterDetails(path, req);
	}

	private void putReqMonWaited(String ppath, MonitorWaitedRequest req, String key) {
		String path = createObject(req, key, ppath);
		putReqMonWaitedDetails(path, req, key);
		insertObject(path);
	}

	private void putReqMonWaitedDetails(String path, MonitorWaitedRequest req, String key) {
		putFilterDetails(path, req);
	}

	private void putFilterDetails(String path, EventRequest req) {
		Object property = req.getProperty("Class");
		if (property != null) {
			if (property instanceof ReferenceType reftype) {
				setValue(path, ATTR_CLASS, reftype.name());
			}
		}
		property = req.getProperty("Instance");
		if (property != null) {
			if (property instanceof ObjectReference ref) {
				setValue(path, ATTR_INSTANCE, ref.toString());
			}
		}
		property = req.getProperty("Thread");
		if (property != null) {
			if (property instanceof ThreadReference ref) {
				setValue(path, ATTR_THREAD, ref.name());
			}
		}
	}

	public void ghidraTracePutModules() {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutModules", false)) {
			putModuleReferenceContainer();
		}
	}

	public void ghidraTracePutClasses() {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutClasses", false)) {
			VirtualMachine vm = connector.getJdi().getCurrentVM();
			putReferenceTypeContainer(getPath(vm) + ".Classes", vm.allClasses());
		}
	}

	public void ghidraTracePutThreads() {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutThreads", false)) {
			VirtualMachine vm = connector.getJdi().getCurrentVM();
			putThreadContainer(getPath(vm), vm.allThreads(), false); // Do this first
			putThreadGroupContainer(getPath(vm), vm.topLevelThreadGroups());
		}
	}

	public void ghidraTracePutFrames() {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutFrames", false)) {
			putFrames();
		}
	}

	public void ghidraTracePutAll() {
		state.requireTrace();
		try (RmiTransaction tx = state.trace.startTx("ghidraTracePutAll", false)) {
			putVMs();
			VirtualMachine vm = connector.getJdi().getCurrentVM();
			putProcesses();
			putThreadContainer(getPath(vm), vm.allThreads(), false);
			putThreadGroupContainer(getPath(vm), vm.topLevelThreadGroups());
			putFrames();
			putBreakpoints();
			putEvents();
			putReferenceTypeContainer(getPath(vm) + ".Classes", vm.allClasses());
		}
	}

	public void ghidraTraceInstallHooks() {
		connector.getHooks().installHooks();
	}

	public void ghidraTraceRemoveHooks() {
		connector.getHooks().removeHooks();
	}

	public void ghidraTraceSyncEnable() {
		try (RmiTransaction tx = state.trace.startTx("ghidraTraceSyncEnable", false)) {
			JdiHooks hooks = connector.getHooks();
			hooks.installHooks();
			hooks.enableCurrentVM();
		}
	}

	public void ghidraTraceSyncDisable() {
		connector.getHooks().disableCurrentVM();
	}

	public void ghidraTraceSyncSynthStopped() {
		connector.getHooks().onStop(null, state.trace);
	}

	public void ghidraTraceWaitStopped(int timeout) {
		ThreadReference currentThread = connector.getJdi().getCurrentThread();
		if (currentThread == null) {
			return;
		}
		long start = System.currentTimeMillis();
		while (!currentThread.isSuspended()) {
			currentThread = connector.getJdi().getCurrentThread();
			try {
				Thread.sleep(100);
				long elapsed = System.currentTimeMillis() - start;
				if (elapsed > timeout) {
					throw new RuntimeException("Timed out waiting for thread to stop");
				}
			}
			catch (InterruptedException e) {
				Msg.error(this, "Wait interrupted");
			}
		}
	}

	public void execute(ClassType ct, ThreadReference thread, Method method, List<Value> args,
			int options) {
		try {
			Value val = ct.invokeMethod(thread, method, args, options);
			System.err.println(val);
		}
		catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	public void execute(ObjectReference ref, ThreadReference thread, Method method,
			List<Value> args, int options) {
		try {
			Value val = ref.invokeMethod(thread, method, args, options);
			System.out.println(val);
		}
		catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	private int getSize(ReferenceType reftype) {
		byte[] cp = reftype.constantPool();
		int sz = 1;
		if (cp != null && cp.length > 0) {
			sz = cp.length;
		}
		return sz;
	}

	public void setValue(String path, String key, Object value) {
		state.trace.setValue(path, key, value);
	}

	String getPath(Object obj) {
		return connector.pathForObj(obj);
	}

	public RmiTraceObject proxyObject(Object obj) {
		String path = getPath(obj);
		return path == null ? null : RmiTraceObject.fromPath(state.trace, path);
	}

	private String createObject(String path) {
		state.trace.createObject(path);
		return path;
	}

	private String createObject(Object obj, String key, String ppath) {
		if (obj == null) {
			return null;
		}
		String path = connector.recordPath(obj, ppath, key);
		state.trace.createObject(path);
		return path;
	}

	private String insertObject(String path) {
		state.trace.insertObject(path);
		return path;
	}

	private void retainKeys(String ppath, Set<String> keys) {
		state.trace.retainValues(ppath, keys, ValueKinds.VK_ELEMENTS);
	}

	public void createLink(Object parent, String label, Object child) {
		String ppath = parent instanceof String ? (String) parent : getPath(parent);
		RmiTraceObject proxy = proxyObject(child);
		if (proxy != null) {
			setValue(ppath, label, proxy);
		}
		else {
			// TODO: is this really what we want to do?			
			String key = child.toString();
			if (child instanceof Method m) {
				key = m.name();
			}
			String lpath = createObject(child, key, ppath + "." + label);
			insertObject(lpath);
		}
	}

	public String getVmPath(VirtualMachine vm) {
		return connector.recordPath(vm, "VMs", vm.name());
	}

	public String getParentPath(String path) {
		String ppath = path.substring(0, path.lastIndexOf("."));
		if (ppath.endsWith(".Relations")) {
			return getParentPath(ppath);
		}
		return ppath;
	}

	public boolean setStatus(Object obj, boolean stopped) {
		String path = getPath(obj);
		if (obj == null || path == null) {
			return stopped;
		}
		boolean suspended = stopped;
		String name = obj.toString();
		if (obj instanceof ThreadReference thread) {
			suspended = thread.isSuspended();
			name = thread.name();
		}
		if (obj instanceof VirtualMachine vm) {
			Event currentEvent = jdi.getCurrentEvent();
			String shortName = vm.name();
			if (shortName.contains(" ")) {
				shortName = vm.name().substring(0, vm.name().indexOf(" "));
			}
			name = currentEvent == null ? shortName : shortName + " [" + currentEvent + "]";
		}
		setValue(path, ATTR_ACCESSIBLE, suspended);
		String annotation = suspended ? "(S)" : "(R)";
		setValue(path, ATTR_DISPLAY, name + " " + annotation);
		String tstate = suspended ? "STOPPED" : "RUNNING";
		setValue(path, ATTR_STATE, tstate);
		stopped |= suspended;
		return stopped;
	}

}
