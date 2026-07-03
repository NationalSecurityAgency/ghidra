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

import java.util.HashMap;
import java.util.Map;

import com.sun.jdi.*;

import ghidra.app.plugin.core.debug.client.tracermi.*;
import ghidra.app.plugin.core.debug.client.tracermi.RmiMethodRegistry.TraceRmiMethod;
import ghidra.dbg.jdi.manager.impl.DebugStatus;
import ghidra.dbg.jdi.manager.impl.JdiManagerImpl;
import ghidra.program.model.address.*;
import ghidra.trace.model.target.schema.PrimitiveTraceObjectSchema;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.util.Msg;

public class JdiConnector {

	private static final int STATIC_METHOD_SEPARATION = 3;
	public static final long BLOCK_SIZE = 0x1000L;
	public static final long DEFAULT_SECTION = 0x0000L;

	public static final String ATTR_DISPLAY = "_display";
	public static final String ATTR_STATE = "_state";
	public static final String ATTR_MODULE_NAME = "_module_name";
	public static final String ATTR_ARCH = "_arch";
	public static final String ATTR_DEBUGGER = "_debugger";
	public static final String ATTR_OS = "_os";
	public static final String ATTR_ENDIAN = "_endian";
	public static final String ATTR_ACCESSIBLE = "_accessible";
	public static final String ATTR_ADDRESS = "Address";
	public static final String ATTR_ALIVE = "Alive";
	public static final String ATTR_CLASS = "Class";
	public static final String ATTR_COMMAND_LINE = "CommandLine";
	public static final String ATTR_COUNT = "Count";
	public static final String ATTR_ENABLED = "Enabled";
	public static final String ATTR_EXECUTABLE = "Executable";
	public static final String ATTR_EXIT_CODE = "ExitCode";
	public static final String ATTR_INDEX = "Index";
	public static final String ATTR_INSTANCE = "Instance";
	public static final String ATTR_LENGTH = "Length";
	public static final String ATTR_LINENO = "LineNo";
	public static final String ATTR_LOCATION = "Location";
	public static final String ATTR_NAME = "Name";
	public static final String ATTR_PC = "PC";
	public static final String ATTR_PLATFORM_ONLY = "PlatformOnly";
	public static final String ATTR_RANGE = "Range";
	public static final String ATTR_RANGE_CP = "RangeCP"; // Constant pool
	public static final String ATTR_SIGNATURE = "Signature";
	public static final String ATTR_THREAD = "Thread";
	public static final String ATTR_TYPE = "Type";
	public static final String ATTR_VALUE = "Value";
	public static final String ATTR_EXCLUDE = "Exclude";
	public static final String ATTR_INCLUDE = "Include";

	private final JdiManagerImpl manager;
	private final JdiArch arch;
	private final JdiHooks hooks;
	private final JdiMethods methods;
	private final JdiCommands commands;

	final Map<String, Object> objectRegistry = new HashMap<>();
	final Map<Object, String> reverseRegistry = new HashMap<>();
	final RmiMethodRegistry remoteMethodRegistry = new RmiMethodRegistry();
	final Map<Object, Boolean> scopeRegistry = new HashMap<>();

	protected final AddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
	protected Long ramIndex = BLOCK_SIZE;
	protected final AddressSpace pool =
		new GenericAddressSpace("constantPool", 64, AddressSpace.TYPE_RAM, 0);
	protected Long poolIndex = 0x0L;
	public final AddressRangeImpl defaultRange;

	private final Map<String, AddressRange> addressRangeByMethod = new HashMap<>();
	private final Map<String, Method> methodsByKey = new HashMap<>();
	private final Map<ReferenceType, AddressRange> addressRangeByClass = new HashMap<>();
	private final Map<ReferenceType, AddressRange> cpAddressRangeByClass = new HashMap<>();

	private final Map<String, DebugStatus> returnStatusMap = new HashMap<>();
	final TraceObjectSchema rootSchema;
	private Map<String, String> env;

	public JdiConnector(JdiManagerImpl manager, Map<String, String> env) {
		this(manager);
		this.env = env;
		commands.ghidraTraceConnect(env.get("GHIDRA_TRACE_RMI_ADDR"));
		commands.ghidraTraceStart(env.get("OPT_TARGET_CLASS"));
	}

	public JdiConnector(JdiManagerImpl manager) {
		this.manager = manager;
		Address start = ram.getAddress(DEFAULT_SECTION);
		defaultRange = new AddressRangeImpl(start, start.add(BLOCK_SIZE - 1));
		rootSchema = RmiClient.loadSchema("jdi_schema.xml", "Debugger");

		arch = new JdiArch(this);
		commands = new JdiCommands(this); // Must precede methods/hooks
		methods = new JdiMethods(this, commands);
		hooks = new JdiHooks(this, commands);
		hooks.installHooks();
	}

	public JdiManagerImpl getJdi() {
		return manager;
	}

	public JdiArch getArch() {
		return arch;
	}

	public JdiCommands getCommands() {
		return commands;
	}

	public JdiMethods getMethods() {
		return methods;
	}

	public JdiHooks getHooks() {
		return hooks;
	}

	public RmiClient getClient() {
		return commands.state.client;
	}

	public Map<String, String> getEnv() {
		return env;
	}

	public void registerRemoteMethod(JdiMethods methods, java.lang.reflect.Method m, String name) {
		TraceRmiMethod annot = m.getAnnotation(TraceRmiMethod.class);
		if (annot == null) {
			return;
		}
		int pcount = m.getParameterCount();
		if (pcount < 1) {
			return;
		}
		/**
		 * TODO: The return type should be reflected from the method; however, none of the parameter
		 * collection routines currently use the return type, so just use ANY for now.
		 */
		TraceObjectSchema schema = PrimitiveTraceObjectSchema.ANY;
		RmiRemoteMethod method = new RmiRemoteMethod(rootSchema.getContext(), name, annot.action(),
			annot.display(), annot.description(), annot.okText(), annot.icon(), schema, methods, m);
		remoteMethodRegistry.putMethod(name, method);
	}

	public AddressSpace getAddressSpace(String name) {
		switch (name) {
			case "ram":
				return ram;
			case "constantPool":
				return pool;
			default:
				return null;
		}
	}

	public AddressRange putAddressRange(ReferenceType cls, AddressSet set) {
		synchronized (addressRangeByClass) {
			if (set.isEmpty()) {
				addressRangeByClass.put(cls, defaultRange);
				return defaultRange;
			}
			AddressRange range = new AddressRangeImpl(set.getMinAddress(), set.getMaxAddress());
			addressRangeByClass.put(cls, range);
			return range;
		}
	}

	public AddressRange getAddressRange(ReferenceType cls) {
		if (cls == null) {
			return defaultRange;
		}
		synchronized (addressRangeByClass) {
			return addressRangeByClass.get(cls);
		}
	}

	public ReferenceType getReferenceTypeForAddress(Address address) {
		synchronized (addressRangeByClass) {
			for (ReferenceType ref : addressRangeByClass.keySet()) {
				AddressRange range = addressRangeByClass.get(ref);
				if (range.contains(address)) {
					return ref;
				}
			}
		}
		return null;
	}

	public AddressRange getPoolAddressRange(ReferenceType cls, int sz) {
		if (cls == null) {
			return defaultRange;
		}
		synchronized (cpAddressRangeByClass) {
			AddressRange range = cpAddressRangeByClass.get(cls);
			if (range == null) {
				registerConstantPool(cls, sz);
				range = cpAddressRangeByClass.get(cls);
			}
			return range;
		}
	}

	public void registerConstantPool(ReferenceType declaringType, int sz) {
		synchronized (cpAddressRangeByClass) {
			if (!cpAddressRangeByClass.containsKey(declaringType)) {
				if (manager.getCurrentVM().canGetConstantPool()) {
					long length = sz == 0 ? 2 : sz;
					Address start = pool.getAddress(poolIndex);
					AddressRangeImpl range =
						new AddressRangeImpl(start, start.add(length - 1));
					if (!cpAddressRangeByClass.containsKey(declaringType)) {
						cpAddressRangeByClass.put(declaringType, range);
						poolIndex += length; //bytecodes.length;
					}
				}
			}
		}
	}

	public ReferenceType getReferenceTypeForPoolAddress(Address address) {
		synchronized (cpAddressRangeByClass) {
			for (ReferenceType ref : cpAddressRangeByClass.keySet()) {
				AddressRange range = cpAddressRangeByClass.get(ref);
				if (range.contains(address)) {
					return ref;
				}
			}
		}
		return null;
	}

	public AddressRange getAddressRange(Method method) {
		if (method == null) {
			return defaultRange;
		}
		synchronized (addressRangeByMethod) {
			AddressRange range = addressRangeByMethod.get(methodToKey(method));
			if (range == null) {
				return defaultRange;
			}
			return range;
		}
	}

	public Method getMethodForAddress(Address address) {
		synchronized (addressRangeByMethod) {
			for (String methodName : addressRangeByMethod.keySet()) {
				AddressRange range = addressRangeByMethod.get(methodName);
				if (range.contains(address)) {
					return methodsByKey.get(methodName);
				}
			}
			return null;
		}
	}

	public Address getAddressFromLocation(Location location) {
		AddressRange addressRange = getAddressRange(location.method());
		if (addressRange == null) {
			return getAddressSpace("ram").getAddress(-1L);
		}
		long codeIndex = location.codeIndex();
		return addressRange.getMinAddress().add(codeIndex < 0 ? 0 : codeIndex);

	}

	public Location getLocation(Address address) {
		Method method = getMethodForAddress(address);
		long codeIndex = address.subtract(getAddressRange(method).getMinAddress());
		return method.locationOfCodeIndex(codeIndex);
	}

	public static String methodToKey(Method method) {
		return method.toString();
	}

	public AddressRange registerAddressesForMethod(Method method) {
		byte[] bytecodes = method.bytecodes();
		if (bytecodes == null) {
			return null;
		}
		int length = bytecodes.length;
		if (length <= 0) {
			return null;
		}
		synchronized (addressRangeByMethod) {
			Address start = ram.getAddress(ramIndex);
			AddressRangeImpl range =
				new AddressRangeImpl(start, start.add(length - 1));
			String key = methodToKey(method);
			//System.err.println(Long.toHexString(ramIndex)+":"+key+":"+bytecodes.length+" "+Long.toHexString(bytecodes[0]));
			if (!methodsByKey.containsKey(key)) {
				methodsByKey.put(key, method);
			}
			if (!addressRangeByMethod.containsKey(key)) {
				addressRangeByMethod.put(key, range);
				ramIndex = range.getMaxAddress().getUnsignedOffset() + STATIC_METHOD_SEPARATION;
				return range;
			}
			return addressRangeByMethod.get(key);
		}
	}

	public String recordPath(Object obj, String path, String key) {
		if (path.endsWith("]")) {
			path += "." + key;
		}
		else {
			path += key(key);
		}
		objectRegistry.put(path, obj);
		if (!reverseRegistry.containsKey(obj)) {
			reverseRegistry.put(obj, path);
		}
		return path;
	}

	public Object objForPath(String path) {
		return objectRegistry.get(path);
	}

	public String pathForObj(Object obj) {
		if (!reverseRegistry.containsKey(obj)) {
			if (objectRegistry.containsValue(obj)) {
				Msg.error(this, "MISSING path for " + obj);
			}
			return null;
		}
		return reverseRegistry.get(obj);
	}

	public boolean getScope(Object ctxt) {
		Boolean scope = scopeRegistry.get(ctxt);
		if (scope == null) {
			scope = true;
		}
		return scope;
	}

	public void toggleScope(Object ctxt) {
		Boolean scope = scopeRegistry.get(ctxt);
		if (scope == null) {
			scope = true;
		}
		scopeRegistry.put(ctxt, !scope);
	}

	private String sanitize(String name) {
		if (name == null) {
			return name;
		}
		name = name.replace("[", "");
		name = name.replace("]", "");
		return name;
	}

	public String key(String key) {
		return "[" + sanitize(key) + "]";
	}

	public DebugStatus getReturnStatus(String eventName) {
		return returnStatusMap.get(eventName);
	}

	public void setReturnStatus(String eventName, String statusString) {
		DebugStatus status = DebugStatus.BREAK;
		try {
			status = DebugStatus.valueOf(statusString.toUpperCase());
		}
		catch (IllegalArgumentException e) {
			// IGNORE
		}
		returnStatusMap.put(eventName, status);
	}

	public void bumpRamIndex() {
		synchronized (addressRangeByMethod) {
			if (ramIndex % BLOCK_SIZE != 0) {
				ramIndex = (ramIndex / BLOCK_SIZE + 1) * BLOCK_SIZE;
			}
		}
	}
}
